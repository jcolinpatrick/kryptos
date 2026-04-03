#!/usr/bin/env python3
"""Script execution tracker — persistent log of all script runs.

Maintains a SQLite database recording:
  - script path
  - run timestamp (UTC)
  - exit code
  - best score (if parseable from output)
  - wall time
  - whether results were saved
  - lifecycle status (running → completed/timeout/crashed/orphaned)
  - PID (for detecting orphaned processes across sessions)

Usage:
  # Record a completed run (legacy interface, still works)
  python3 scripts/_infra/script_tracker.py record <script_path> [--exit-code N] [--score N] [--wall-time N]

  # List unrun scripts (scripts that exist but have no record)
  python3 scripts/_infra/script_tracker.py unrun

  # Show run history for a script
  python3 scripts/_infra/script_tracker.py history <script_path>

  # Summary: count runs per script
  python3 scripts/_infra/script_tracker.py summary

  # Audit: find scripts with no results in results/ folder
  python3 scripts/_infra/script_tracker.py audit

  # Show currently running scripts (status='running' with live PID)
  python3 scripts/_infra/script_tracker.py active

  # Detect and mark orphaned runs (PID dead but status still 'running')
  python3 scripts/_infra/script_tracker.py check-stale

The database lives at db/script_runs.sqlite (symlinked to /data/db/).
"""
import argparse
import datetime
import os
import re
import signal
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = _ROOT / "db" / "script_runs.sqlite"


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_path TEXT NOT NULL,
            run_ts TEXT NOT NULL,
            exit_code INTEGER,
            best_score REAL,
            wall_time_s REAL,
            has_results INTEGER DEFAULT 0,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_runs_script ON runs(script_path)
    """)
    # Migrate: add status and pid columns if missing
    cols = {row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()}
    if "status" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN status TEXT DEFAULT 'completed'")
    if "pid" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN pid INTEGER")
    conn.commit()
    return conn


def _pid_alive(pid):
    """Check if a process with the given PID is still running."""
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def start_run(script_path, pid=None):
    """Record a script starting. Returns the run ID for later finish_run()."""
    conn = get_db()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO runs (script_path, run_ts, status, pid) VALUES (?, ?, 'running', ?)",
        (script_path, ts, pid),
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finish_run(run_id, exit_code=None, best_score=None,
               wall_time=None, has_results=False, notes=None, status=None):
    """Mark a previously started run as completed/timeout/crashed."""
    if status is None:
        if exit_code == -2:
            status = "timeout"
        elif exit_code is not None and exit_code != 0:
            status = "crashed"
        else:
            status = "completed"
    conn = get_db()
    conn.execute(
        "UPDATE runs SET exit_code=?, best_score=?, wall_time_s=?, "
        "has_results=?, notes=?, status=? WHERE id=?",
        (exit_code, best_score, wall_time, int(has_results), notes, status, run_id),
    )
    conn.commit()
    conn.close()


def record_run(script_path, exit_code=None, best_score=None,
               wall_time=None, has_results=False, notes=None):
    """Legacy interface: record a completed run in one call."""
    conn = get_db()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if exit_code == -2:
        status = "timeout"
    elif exit_code is not None and exit_code != 0:
        status = "crashed"
    else:
        status = "completed"
    conn.execute(
        "INSERT INTO runs (script_path, run_ts, exit_code, best_score, wall_time_s, "
        "has_results, notes, status, pid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (script_path, ts, exit_code, best_score, wall_time, int(has_results), notes, status, None),
    )
    conn.commit()
    conn.close()


def find_active_runs():
    """Find runs marked as 'running'. Cross-references PIDs to check liveness."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, script_path, run_ts, pid FROM runs WHERE status = 'running' ORDER BY run_ts DESC"
    ).fetchall()
    conn.close()
    results = []
    for run_id, path, ts, pid in rows:
        alive = _pid_alive(pid)
        results.append({
            "id": run_id, "script_path": path, "run_ts": ts,
            "pid": pid, "pid_alive": alive,
        })
    return results


def check_stale_runs(fix=False):
    """Detect runs stuck in 'running' whose PID is dead. Optionally mark them orphaned."""
    active = find_active_runs()
    stale = [r for r in active if not r["pid_alive"]]
    if fix and stale:
        conn = get_db()
        for r in stale:
            conn.execute(
                "UPDATE runs SET status = 'orphaned', notes = COALESCE(notes || '; ', '') || ? WHERE id = ?",
                (f"orphaned: PID {r['pid']} dead at check_stale", r["id"]),
            )
        conn.commit()
        conn.close()
    return stale


def find_all_scripts():
    """Find all experiment scripts in scripts/."""
    scripts = []
    for root, dirs, files in os.walk(_ROOT / "scripts"):
        # Skip infrastructure and examples
        relroot = os.path.relpath(root, _ROOT / "scripts")
        if relroot.startswith("_infra") or relroot.startswith("examples"):
            continue
        for f in sorted(files):
            if f.endswith(".py") and (f.startswith("e_") or f.startswith("f_") or f.startswith("blitz_")):
                relpath = os.path.relpath(os.path.join(root, f), _ROOT)
                scripts.append(relpath)
    return scripts


def find_unrun_scripts():
    """Find scripts that have never been recorded as run."""
    conn = get_db()
    all_scripts = find_all_scripts()
    run_scripts = set(
        row[0] for row in conn.execute("SELECT DISTINCT script_path FROM runs").fetchall()
    )
    conn.close()
    return [s for s in all_scripts if s not in run_scripts]


def show_history(script_path):
    conn = get_db()
    rows = conn.execute(
        "SELECT run_ts, exit_code, best_score, wall_time_s, has_results, notes, status, pid "
        "FROM runs WHERE script_path = ? ORDER BY run_ts DESC",
        (script_path,),
    ).fetchall()
    conn.close()
    if not rows:
        print(f"No runs recorded for: {script_path}")
        return
    print(f"Run history for {script_path}:")
    for ts, ec, score, wt, hr, notes, status, pid in rows:
        parts = [f"  {ts[:19]}"]
        if status:
            parts.append(f"[{status}]")
        if pid is not None:
            parts.append(f"pid={pid}")
        if ec is not None:
            parts.append(f"exit={ec}")
        if score is not None:
            parts.append(f"score={score}")
        if wt is not None:
            parts.append(f"time={wt:.1f}s")
        if hr:
            parts.append("results=yes")
        if notes:
            parts.append(f"notes={notes}")
        print("  ".join(parts))


def show_summary():
    conn = get_db()
    rows = conn.execute("""
        SELECT script_path, COUNT(*) as n_runs,
               MAX(best_score) as max_score,
               MAX(run_ts) as last_run
        FROM runs GROUP BY script_path ORDER BY last_run DESC
    """).fetchall()
    conn.close()
    print(f"{'Script':<60s} {'Runs':>5s} {'Best':>6s} {'Last Run':>20s}")
    print("-" * 95)
    for path, n, score, last in rows:
        score_str = f"{score:.0f}" if score is not None else "-"
        print(f"{path:<60s} {n:>5d} {score_str:>6s} {last[:19]:>20s}")


def audit_results():
    """Find scripts that have run records but no corresponding results files."""
    conn = get_db()
    scripts = conn.execute("SELECT DISTINCT script_path FROM runs").fetchall()
    conn.close()

    results_dir = _ROOT / "results"
    missing = []
    for (script_path,) in scripts:
        basename = Path(script_path).stem
        # Check for any matching results file
        found = False
        if results_dir.exists():
            for f in results_dir.iterdir():
                if basename in f.name:
                    found = True
                    break
        if not found:
            missing.append(script_path)

    if missing:
        print(f"Scripts with run records but no results file ({len(missing)}):")
        for s in sorted(missing):
            print(f"  {s}")
    else:
        print("All recorded scripts have corresponding results files.")


def main():
    parser = argparse.ArgumentParser(description="Script execution tracker")
    sub = parser.add_subparsers(dest="cmd")

    p_record = sub.add_parser("record", help="Record a script run")
    p_record.add_argument("script_path")
    p_record.add_argument("--exit-code", type=int)
    p_record.add_argument("--score", type=float)
    p_record.add_argument("--wall-time", type=float)
    p_record.add_argument("--has-results", action="store_true")
    p_record.add_argument("--notes", type=str)

    sub.add_parser("unrun", help="List unrun scripts")
    p_hist = sub.add_parser("history", help="Show run history")
    p_hist.add_argument("script_path")
    sub.add_parser("summary", help="Summary of all runs")
    sub.add_parser("audit", help="Find scripts without results")
    sub.add_parser("active", help="Show currently running scripts")
    p_stale = sub.add_parser("check-stale", help="Detect orphaned runs (dead PID, still 'running')")
    p_stale.add_argument("--fix", action="store_true", help="Mark stale runs as 'orphaned'")

    args = parser.parse_args()

    if args.cmd == "record":
        record_run(args.script_path, args.exit_code, args.score,
                   args.wall_time, args.has_results, args.notes)
        print(f"Recorded run: {args.script_path}")
    elif args.cmd == "unrun":
        unrun = find_unrun_scripts()
        print(f"Scripts with no run record ({len(unrun)}):")
        for s in unrun:
            print(f"  {s}")
    elif args.cmd == "history":
        show_history(args.script_path)
    elif args.cmd == "summary":
        show_summary()
    elif args.cmd == "audit":
        audit_results()
    elif args.cmd == "active":
        active = find_active_runs()
        if not active:
            print("No scripts currently marked as running.")
        else:
            print(f"Scripts marked as running ({len(active)}):")
            for r in active:
                pid_status = "ALIVE" if r["pid_alive"] else "DEAD"
                pid_str = f"pid={r['pid']} ({pid_status})" if r['pid'] else "pid=unknown"
                print(f"  {r['script_path']}  started={r['run_ts'][:19]}  {pid_str}")
    elif args.cmd == "check-stale":
        stale = check_stale_runs(fix=args.fix)
        if not stale:
            print("No stale runs found (all 'running' entries have live PIDs or none are running).")
        else:
            action = "Marked as orphaned" if args.fix else "Would mark as orphaned (use --fix to apply)"
            print(f"Stale runs ({len(stale)}): {action}")
            for r in stale:
                print(f"  [id={r['id']}] {r['script_path']}  pid={r['pid']}  started={r['run_ts'][:19]}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
