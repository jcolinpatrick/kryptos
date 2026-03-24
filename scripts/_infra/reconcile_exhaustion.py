#!/usr/bin/env python3
"""Reconcile all scripts on disk into exhaustion_log.json.

Finds scripts missing from the exhaustion log, parses their headers
(if present), infers metadata from directory structure, and adds them.

Usage:
    PYTHONPATH=src python3 scripts/_infra/reconcile_exhaustion.py --dry-run
    PYTHONPATH=src python3 scripts/_infra/reconcile_exhaustion.py --apply
    PYTHONPATH=src python3 scripts/_infra/reconcile_exhaustion.py --apply --status active
"""

import sys
import os
import argparse
import json
import re
from pathlib import Path
from datetime import datetime

_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, str(_ROOT))

from scripts.lib.header import parse_header, extract_legacy_description
from scripts.lib.exhaustion import load, save

SKIP_DIRS = {"__pycache__", "lib", "_infra", "examples"}
SKIP_FILES = {"__init__.py", "conftest.py"}


def discover_all_scripts() -> list[dict]:
    """Find all .py scripts in scripts/, with family from directory."""
    scripts_dir = _ROOT / "scripts"
    found = []
    for py in sorted(scripts_dir.rglob("*.py")):
        rel = py.relative_to(scripts_dir)
        parts = rel.parts
        if any(p in SKIP_DIRS for p in parts):
            continue
        if py.name in SKIP_FILES:
            continue
        if len(parts) < 2:
            continue
        # Family from first directory level
        family = parts[0]
        # Sub-family if 3+ levels deep
        if len(parts) >= 3:
            family = f"{parts[0]}/{parts[1]}"
        found.append({
            "script_id": py.stem,
            "family": family,
            "path": str(py),
            "rel_path": str(rel),
        })
    return found


def check_for_results(script_id: str) -> dict:
    """Check if a result file exists for this script."""
    results_dir = _ROOT / "results"
    info = {"has_result": False, "best_score": None}
    for pattern in [f"{script_id}.json", f"{script_id}_results.json",
                    f"e_{script_id}.json", f"f_{script_id}.json"]:
        candidate = results_dir / pattern
        if candidate.exists():
            info["has_result"] = True
            try:
                data = json.loads(candidate.read_text())
                for key in ("best_score", "score", "crib_score", "best"):
                    val = data.get(key) if isinstance(data, dict) else None
                    if isinstance(val, (int, float)):
                        if info["best_score"] is None or val > info["best_score"]:
                            info["best_score"] = val
            except (json.JSONDecodeError, OSError):
                pass
            break
    return info


def reconcile(dry_run: bool, default_status: str = "active"):
    """Find untracked scripts and add them to exhaustion_log.json."""
    log = load()
    tracked_ids = set(log.keys())
    all_scripts = discover_all_scripts()

    untracked = [s for s in all_scripts if s["script_id"] not in tracked_ids]

    if not untracked:
        print("All scripts are tracked. Nothing to do.")
        return

    print(f"Found {len(untracked)} untracked scripts across "
          f"{len(set(s['family'] for s in untracked))} families.\n")

    # Categorize
    with_header = []
    without_header = []
    additions = {}

    for s in untracked:
        sid = s["script_id"]
        header = parse_header(s["path"])
        result_info = check_for_results(sid)

        if header:
            entry = {
                "description": f"{sid}.py",
                "family": header.family,
                "status": header.status if header.status in {"exhausted", "active", "promising"} else default_status,
            }
            if header.keyspace:
                entry["keyspace"] = header.keyspace
            # Only store last_run if it looks like a date (YYYY-MM-DD)
            if header.last_run and re.match(r"^\d{4}-\d{2}-\d{2}", header.last_run):
                entry["last_run"] = header.last_run
            with_header.append(sid)
        else:
            # Infer from directory and file
            desc = extract_legacy_description(s["path"])
            entry = {
                "description": f"{sid}.py" + (f" — {desc}" if desc else ""),
                "family": s["family"],
                "status": default_status,
            }
            without_header.append(sid)

        # Enrich with result data
        if result_info["has_result"]:
            if result_info["best_score"] is not None:
                entry["best"] = result_info["best_score"]
            entry["has_result"] = True

        additions[sid] = entry

    # Summary by family
    family_counts = {}
    for s in untracked:
        fam = additions[s["script_id"]]["family"]
        family_counts[fam] = family_counts.get(fam, 0) + 1

    print(f"  With standard header:    {len(with_header)}")
    print(f"  Without header (inferred): {len(without_header)}")
    print()
    print("BY FAMILY:")
    for fam, count in sorted(family_counts.items(), key=lambda x: -x[1]):
        print(f"  {fam:<30} {count:>4}")
    print()

    # Status breakdown
    status_counts = {}
    for entry in additions.values():
        st = entry["status"]
        status_counts[st] = status_counts.get(st, 0) + 1
    print("STATUS BREAKDOWN:")
    for st, count in sorted(status_counts.items()):
        print(f"  {st:<15} {count:>4}")
    print()

    if dry_run:
        print("DRY RUN — no changes written.")
        print(f"Would add {len(additions)} entries to exhaustion_log.json")
        print(f"  (current: {len(log)} → new total: {len(log) + len(additions)})")
        # Show a few examples
        print("\nSample entries:")
        for sid in list(additions.keys())[:5]:
            print(f"  {sid}: {json.dumps(additions[sid])}")
        return

    # Apply
    log.update(additions)
    save(log)
    print(f"APPLIED: Added {len(additions)} entries to exhaustion_log.json")
    print(f"  Total entries: {len(log)}")


def main():
    parser = argparse.ArgumentParser(
        description="Reconcile scripts on disk with exhaustion_log.json"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Show what would be added")
    mode.add_argument("--apply", action="store_true", help="Add untracked scripts to log")
    parser.add_argument(
        "--status", default="active", choices=["active", "promising", "exhausted"],
        help="Default status for scripts without headers (default: active)"
    )
    args = parser.parse_args()
    reconcile(dry_run=args.dry_run, default_status=args.status)


if __name__ == "__main__":
    main()
