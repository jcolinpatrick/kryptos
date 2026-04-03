#!/usr/bin/env python3
"""Batch script runner — discovers and runs unexecuted experiment scripts.

Finds all experiment scripts (e_*, f_*, blitz_*) that have no run record
in the tracker database, runs them sequentially with timeout protection,
captures output and scores, and records results.

Usage:
  PYTHONPATH=src python3 -u scripts/_infra/batch_runner.py [--timeout 300] [--dry-run] [--skip PATTERN]

Options:
  --timeout N    Max seconds per script (default: 300 = 5 min)
  --dry-run      List scripts that would run, don't execute
  --skip PATTERN Skip scripts matching this substring
  --family FAM   Only run scripts in this family/subdirectory
  --limit N      Max scripts to run (for testing)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts" / "_infra"))

from script_tracker import (
    record_run, find_unrun_scripts, find_all_scripts, get_db,
    start_run, finish_run, check_stale_runs,
)

# Scripts to always skip (known long-running, interactive, or infrastructure)
ALWAYS_SKIP = {
    "scripts/_infra/",
    "scripts/examples/",
    "campaign",  # Campaign scripts are orchestrators, not standalone experiments
    "corpus_pipeline",
    "parse_mbox",
    "k4_word_search",
    "k4_clock_cipher",
    "audit_scripts",
    "session_briefing",
    "batch_runner",
    "script_tracker",
}

# Scripts known to be extremely long-running (>30 min) — skip unless forced
LONG_RUNNING = {
    "gutenberg_sweep",
    "rosetta_running_key",
    "isbn_hunt",
    "berlin_wall_crib_drag",
    "exhaustive_02",
    "exhaustive_palette",
    "running_key_crib_drag",
    "corpus",
}


def should_skip(script_path, skip_patterns, skip_long=True):
    """Decide whether to skip a script."""
    for pattern in ALWAYS_SKIP:
        if pattern in script_path:
            return True, f"infrastructure/skip-list ({pattern})"

    if skip_long:
        for pattern in LONG_RUNNING:
            if pattern in script_path:
                return True, f"long-running ({pattern})"

    for pattern in skip_patterns:
        if pattern in script_path:
            return True, f"user skip ({pattern})"

    return False, ""


def parse_score_from_output(output):
    """Try to extract best score from script output."""
    # Look for common patterns
    patterns = [
        r"[Bb]est\s+(?:score|crib)[:\s]*(\d+)/24",
        r"score[=:]\s*(\d+)/24",
        r"BEST.*?(\d+)/24",
        r"Global best.*?(\d+)/24",
        r"best=(\d+)/24",
    ]
    best = None
    for pat in patterns:
        for m in re.finditer(pat, output):
            val = int(m.group(1))
            if best is None or val > best:
                best = val
    return best


def run_script(script_path, timeout_s=300):
    """Run a single script and capture results."""
    full_path = _ROOT / script_path
    if not full_path.exists():
        return {"error": f"File not found: {full_path}", "exit_code": -1}

    env = os.environ.copy()
    env["PYTHONPATH"] = str(_ROOT / "src")

    t0 = time.time()
    try:
        result = subprocess.run(
            [sys.executable, "-u", str(full_path)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
            cwd=str(_ROOT),
        )
        wall_time = time.time() - t0
        output = result.stdout + result.stderr
        score = parse_score_from_output(output)

        return {
            "exit_code": result.returncode,
            "wall_time": wall_time,
            "score": score,
            "output_tail": output[-500:] if output else "",
            "has_results": "results/" in output or "saved" in output.lower(),
        }
    except subprocess.TimeoutExpired:
        wall_time = time.time() - t0
        return {
            "exit_code": -2,
            "wall_time": wall_time,
            "score": None,
            "output_tail": f"TIMEOUT after {timeout_s}s",
            "has_results": False,
        }
    except Exception as e:
        wall_time = time.time() - t0
        return {
            "exit_code": -3,
            "wall_time": wall_time,
            "score": None,
            "output_tail": str(e)[-500:],
            "has_results": False,
        }


def main():
    parser = argparse.ArgumentParser(description="Batch script runner")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout per script (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="List scripts without running")
    parser.add_argument("--skip", action="append", default=[], help="Skip scripts matching pattern")
    parser.add_argument("--family", type=str, help="Only run scripts in this family")
    parser.add_argument("--limit", type=int, help="Max scripts to run")
    parser.add_argument("--include-long", action="store_true", help="Include long-running scripts")
    parser.add_argument("--all", action="store_true", help="Run ALL scripts, not just unrun ones")
    args = parser.parse_args()

    print("=" * 70)
    print("BATCH SCRIPT RUNNER")
    print(f"Timeout: {args.timeout}s per script")
    print("=" * 70)

    if args.all:
        candidates = find_all_scripts()
        print(f"Mode: ALL scripts ({len(candidates)} total)")
    else:
        candidates = find_unrun_scripts()
        print(f"Mode: UNRUN scripts ({len(candidates)} with no run record)")

    if args.family:
        candidates = [s for s in candidates if args.family in s]
        print(f"Filtered to family '{args.family}': {len(candidates)} scripts")

    # Filter
    to_run = []
    skipped = []
    for script in candidates:
        skip, reason = should_skip(script, args.skip, skip_long=not args.include_long)
        if skip:
            skipped.append((script, reason))
        else:
            to_run.append(script)

    if args.limit:
        to_run = to_run[:args.limit]

    print(f"\nTo run: {len(to_run)}")
    print(f"Skipped: {len(skipped)}")

    if args.dry_run:
        print("\n--- WOULD RUN ---")
        for s in to_run:
            print(f"  {s}")
        print(f"\n--- SKIPPED ---")
        for s, reason in skipped[:20]:
            print(f"  {s} ({reason})")
        if len(skipped) > 20:
            print(f"  ... and {len(skipped) - 20} more")
        return

    # Run
    total = len(to_run)
    successes = 0
    failures = 0
    timeouts = 0
    best_overall = 0
    t_start = time.time()

    for i, script in enumerate(to_run):
        print(f"\n[{i+1}/{total}] {script}", flush=True)

        # Record start BEFORE execution so other sessions can see it
        run_id = start_run(script, pid=os.getpid())
        result = run_script(script, args.timeout)

        ec = result["exit_code"]
        wt = result["wall_time"]
        score = result["score"]

        if ec == 0:
            successes += 1
            status = "OK"
        elif ec == -2:
            timeouts += 1
            status = "TIMEOUT"
        else:
            failures += 1
            status = f"FAIL(exit={ec})"

        score_str = f"score={score}/24" if score is not None else "no score"
        print(f"  {status} | {wt:.1f}s | {score_str}", flush=True)

        if score is not None and score > best_overall:
            best_overall = score
            print(f"  *** NEW SESSION BEST: {score}/24 ***")

        # Update the run record with results
        finish_run(
            run_id,
            exit_code=ec,
            best_score=score,
            wall_time=wt,
            has_results=result.get("has_results", False),
            notes=status,
        )

        # Print tail on failure
        if ec != 0 and result.get("output_tail"):
            tail = result["output_tail"][-200:]
            print(f"  Output: ...{tail}")

    elapsed = time.time() - t_start
    print(f"\n{'=' * 70}")
    print(f"BATCH COMPLETE")
    print(f"  Total: {total} | OK: {successes} | FAIL: {failures} | TIMEOUT: {timeouts}")
    print(f"  Best score: {best_overall}/24")
    print(f"  Wall time: {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
