#!/usr/bin/env python3
"""
K4 Attack Status Dashboard — Results Consolidation

Scans exhaustion_log.json, scripts/, results/, databases, and
elimination_tiers.md to produce a unified status dashboard.

Usage:
    python3 scripts/_infra/consolidate_results.py
    python3 scripts/_infra/consolidate_results.py --family grille
    python3 scripts/_infra/consolidate_results.py --untracked
    python3 scripts/_infra/consolidate_results.py --open --json -o report.json
"""

import sys
import os
import argparse
import json
import sqlite3
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

SKIP_DIRS = {"__pycache__", "lib", "_infra", "examples"}


# ── Data collection ──────────────────────────────────────────────────────────


def load_exhaustion_log() -> dict:
    """Load exhaustion_log.json from project root."""
    path = _ROOT / "exhaustion_log.json"
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"  Warning: exhaustion_log.json: {exc}", file=sys.stderr)
        return {}


def discover_scripts() -> list[dict]:
    """Walk scripts/ for .py files, extracting script_id and family."""
    scripts_dir = _ROOT / "scripts"
    found = []
    if not scripts_dir.is_dir():
        return found
    for py_file in sorted(scripts_dir.rglob("*.py")):
        rel = py_file.relative_to(scripts_dir)
        parts = rel.parts
        # Skip excluded directories
        if any(part in SKIP_DIRS for part in parts):
            continue
        # Only include files inside a subdirectory (family/script.py)
        if len(parts) < 2:
            continue
        family = parts[0]
        script_id = py_file.stem
        found.append({
            "script_id": script_id,
            "family": family,
            "path": str(py_file.relative_to(_ROOT)),
        })
    return found


def scan_results() -> dict[str, dict]:
    """Scan results/ for JSON files, extract best scores keyed by script_id."""
    results_dir = _ROOT / "results"
    scores = {}
    if not results_dir.is_dir():
        return scores
    for json_file in results_dir.glob("**/*.json"):
        script_id = json_file.stem
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        best = _extract_score(data)
        mtime = datetime.fromtimestamp(json_file.stat().st_mtime, tz=timezone.utc)
        scores[script_id] = {"best_score": best, "date": mtime.strftime("%Y-%m-%d")}
    return scores


def _extract_score(data) -> float | None:
    """Pull the best score from a result JSON (tolerant of varied schemas)."""
    candidates = []
    if isinstance(data, dict):
        for key in ("score", "best_score", "crib_score", "best"):
            val = data.get(key)
            if isinstance(val, (int, float)):
                candidates.append(float(val))
        # Check nested results lists
        for key in ("results", "top_results", "candidates"):
            items = data.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        for skey in ("score", "best_score", "crib_score"):
                            val = item.get(skey)
                            if isinstance(val, (int, float)):
                                candidates.append(float(val))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                s = _extract_score(item)
                if s is not None:
                    candidates.append(s)
    return max(candidates) if candidates else None


def query_database(db_path: Path, table: str) -> dict | None:
    """Query a database for hypothesis count and status breakdown."""
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
        total = cur.fetchone()[0]
        cur = conn.execute(
            f"SELECT status, COUNT(*) FROM {table} GROUP BY status"  # noqa: S608
        )
        breakdown = {row[0]: row[1] for row in cur.fetchall()}
        conn.close()
        return {"total": total, "breakdown": breakdown}
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
        return {"total": 0, "breakdown": {}, "error": str(exc)}


def parse_open_hypotheses() -> list[str]:
    """Extract open hypothesis descriptions from elimination_tiers.md."""
    path = _ROOT / "docs" / "elimination_tiers.md"
    hypotheses = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        return hypotheses
    # Look for Tier 4 (untested) items — lines starting with "- **"
    in_tier4 = False
    for line in text.splitlines():
        if re.match(r"^##.*[Tt]ier\s*4", line):
            in_tier4 = True
        elif re.match(r"^##", line) and in_tier4:
            in_tier4 = False
        if in_tier4 and line.startswith("- **"):
            # Strip markdown bold markers
            desc = re.sub(r"\*\*", "", line.lstrip("- ")).strip()
            # Remove trailing colon content for brevity
            desc = re.split(r"\s*—\s*", desc)[0].rstrip(":").strip()
            if desc:
                hypotheses.append(desc)
    return hypotheses


# ── Aggregation ──────────────────────────────────────────────────────────────


def build_dashboard(args) -> dict:
    """Collect all data and build the dashboard dict."""
    log = load_exhaustion_log()
    scripts = discover_scripts()
    results = scan_results()

    # Build per-family aggregation
    tracked_ids = set(log.keys())
    script_ids_on_disk = {s["script_id"] for s in scripts}

    families = defaultdict(lambda: {
        "total": 0, "tracked": 0,
        "exhausted": 0, "active": 0, "promising": 0,
        "best_score": None, "scripts": [],
    })

    for s in scripts:
        fam = s["family"]
        sid = s["script_id"]
        families[fam]["total"] += 1
        families[fam]["scripts"].append(s)

        entry = log.get(sid)
        if entry:
            families[fam]["tracked"] += 1
            status = entry.get("status", "").lower()
            if status in ("exhausted", "active", "promising"):
                families[fam][status] += 1

        # Merge result scores
        r = results.get(sid)
        if r and r["best_score"] is not None:
            cur = families[fam]["best_score"]
            if cur is None or r["best_score"] > cur:
                families[fam]["best_score"] = r["best_score"]

    # Also account for log entries whose family we know but script isn't on disk
    for sid, entry in log.items():
        if sid not in script_ids_on_disk:
            fam = entry.get("family", "_unknown")
            # Normalize family: strip slashes, take first component
            fam = fam.split("/")[0] if "/" in fam else fam

    # Untracked scripts
    untracked = [s for s in scripts if s["script_id"] not in tracked_ids]

    # Status counts from log
    status_counts = defaultdict(int)
    for entry in log.values():
        status_counts[entry.get("status", "unknown")] += 1

    # Databases
    db_results = query_database(
        _ROOT / "db" / "kryptosbot_results.db", "hypotheses"
    )
    db_novelty = query_database(
        _ROOT / "db" / "novelty_ledger.sqlite", "hypotheses"
    )

    # Open hypotheses
    open_hyps = parse_open_hypotheses()

    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "overview": {
            "scripts_on_disk": len(scripts),
            "tracked_in_log": len(tracked_ids),
            "untracked": len(untracked),
            "untracked_pct": (
                round(100 * len(untracked) / len(scripts), 1)
                if scripts else 0
            ),
            "exhausted": status_counts.get("exhausted", 0),
            "active": status_counts.get("active", 0),
            "promising": status_counts.get("promising", 0),
        },
        "families": {
            k: {key: val for key, val in v.items() if key != "scripts"}
            for k, v in sorted(families.items())
        },
        "families_detail": dict(sorted(families.items())),
        "untracked": [s["path"] for s in untracked],
        "databases": {
            "kryptosbot_results": db_results,
            "novelty_ledger": db_novelty,
        },
        "open_hypotheses": open_hyps,
    }


# ── Filtering ────────────────────────────────────────────────────────────────


def apply_filters(dashboard: dict, args) -> dict:
    """Apply CLI filters to the dashboard data."""
    if args.family:
        fam = args.family.lower()
        dashboard["families"] = {
            k: v for k, v in dashboard["families"].items()
            if k.lower() == fam
        }
        dashboard["families_detail"] = {
            k: v for k, v in dashboard["families_detail"].items()
            if k.lower() == fam
        }
        dashboard["untracked"] = [
            p for p in dashboard["untracked"]
            if f"scripts/{fam}/" in p.lower()
        ]

    if args.untracked:
        # Keep only untracked-relevant data
        dashboard["_mode"] = "untracked"

    if args.open:
        # Filter families to non-exhausted only
        dashboard["families"] = {
            k: v for k, v in dashboard["families"].items()
            if v.get("active", 0) > 0 or v.get("promising", 0) > 0
        }

    return dashboard


# ── Formatting ───────────────────────────────────────────────────────────────


def _fmt_db(info: dict | None) -> str:
    """Format a database status line."""
    if info is None:
        return "not found"
    if "error" in info:
        return f"error: {info['error']}"
    parts = [f"{info['total']} hypotheses"]
    if info["breakdown"]:
        bd = ", ".join(f"{v} {k}" for k, v in sorted(info["breakdown"].items()))
        parts.append(f"({bd})")
    return " ".join(parts)


def _fmt_score(score: float | None) -> str:
    if score is None:
        return "  -"
    if score == int(score):
        return f"{int(score)}/24"
    return f"{score:.1f}"


def format_text(dashboard: dict, args) -> str:
    """Render the dashboard as formatted text."""
    lines = []
    w = 59

    lines.append("=" * w)
    lines.append(f"  K4 ATTACK STATUS DASHBOARD -- {dashboard['date']}")
    lines.append("=" * w)
    lines.append("")

    ov = dashboard["overview"]
    lines.append("OVERVIEW")
    lines.append(f"  Scripts on disk:    {ov['scripts_on_disk']}")
    lines.append(f"  Tracked in log:     {ov['tracked_in_log']}")
    lines.append(f"  UNTRACKED:          {ov['untracked']} ({ov['untracked_pct']}%)")
    lines.append("")
    lines.append(f"  Exhausted:          {ov['exhausted']}")
    lines.append(f"  Active:             {ov['active']}")
    lines.append(f"  Promising:          {ov['promising']}")
    lines.append("")

    # Databases
    db = dashboard["databases"]
    lines.append("DATABASE STATUS")
    lines.append(f"  kryptosbot_results: {_fmt_db(db.get('kryptosbot_results'))}")
    lines.append(f"  novelty_ledger:     {_fmt_db(db.get('novelty_ledger'))}")
    lines.append("")

    # By family table
    fams = dashboard["families"]
    if fams:
        lines.append("BY FAMILY")
        hdr = f"  {'Family':<20} {'Total':>5} {'Tracked':>7} {'Exh':>5} {'Act':>5} {'Prom':>5} {'Best':>6}"
        lines.append(hdr)
        lines.append("  " + "-" * (len(hdr) - 2))
        for name, f in fams.items():
            lines.append(
                f"  {name:<20} {f['total']:>5} {f['tracked']:>7}"
                f" {f['exhausted']:>5} {f['active']:>5} {f['promising']:>5}"
                f" {_fmt_score(f.get('best_score')):>6}"
            )
        lines.append("")

    # Untracked
    untracked = dashboard["untracked"]
    if untracked and (args.untracked or dashboard.get("_mode") == "untracked"):
        lines.append(f"UNTRACKED SCRIPTS ({len(untracked)})")
        for p in sorted(untracked):
            lines.append(f"  {p}")
        lines.append("")

    # Open hypotheses
    hyps = dashboard.get("open_hypotheses", [])
    if hyps and not args.untracked:
        lines.append("OPEN HYPOTHESES (from elimination_tiers.md)")
        for h in hyps:
            lines.append(f"  * {h}")
        lines.append("")

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="K4 Attack Status Dashboard — results consolidation"
    )
    parser.add_argument(
        "--family", type=str, default=None,
        help="Filter output to a specific cipher family",
    )
    parser.add_argument(
        "--untracked", action="store_true",
        help="Show only scripts not in exhaustion_log.json",
    )
    parser.add_argument(
        "--open", action="store_true",
        help="Show only open (non-exhausted) hypotheses",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON instead of formatted text",
    )
    parser.add_argument(
        "-o", type=str, default=None, metavar="FILE",
        help="Write output to file (default: stdout)",
    )
    args = parser.parse_args()

    dashboard = build_dashboard(args)
    dashboard = apply_filters(dashboard, args)

    # Remove internal detail key from JSON output
    clean = {k: v for k, v in dashboard.items() if k not in ("families_detail", "_mode")}

    if args.json:
        output = json.dumps(clean, indent=2, default=str)
    else:
        output = format_text(dashboard, args)

    if args.o:
        Path(args.o).parent.mkdir(parents=True, exist_ok=True)
        Path(args.o).write_text(output + "\n")
        print(f"Written to {args.o}")
    else:
        print(output)


if __name__ == "__main__":
    main()
