#!/usr/bin/env python3
"""Central dispatch runner for K4 attack scripts.

Discovers, filters, and invokes attack scripts by family/status rather
than by manually selecting individual files.

Usage:
    # List all scripts with metadata
    python run_attack.py --list

    # List with verbose stats (families, statuses, migration progress)
    python run_attack.py --list --verbose

    # Filter by family
    python run_attack.py --list --family transposition

    # Filter by status
    python run_attack.py --list --status active

    # Run all active scripts in a family
    python run_attack.py --run --family grille --status active

    # Run with score threshold (only report results above this)
    python run_attack.py --run --family transposition --min-score 700

    # Run a single script by ID
    python run_attack.py --run --id e_frac_05_mixed_alphabets

    # Generate manifest JSON
    python run_attack.py --manifest

    # Reconcile headers vs exhaustion log
    python run_attack.py --reconcile

    # Show exhaustion log summary
    python run_attack.py --exhaustion-summary

Scripts with a standard attack() function are called directly.
Legacy scripts without attack() are invoked via subprocess (python3 -u).
"""

import argparse
import importlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from scripts.lib.discover import (
    build_manifest,
    filter_manifest,
    print_manifest_table,
)
from scripts.lib.exhaustion import (
    load as load_exhaustion,
    record_run,
    reconcile,
)
from scripts.lib.header import parse_header

SCRIPTS_DIR = PROJECT_ROOT / "scripts"


def load_attack_module(script_path: Path):
    """Dynamically import a script and return its module.

    Returns None if import fails.
    """
    spec = importlib.util.spec_from_file_location(
        f"attack_{script_path.stem}", str(script_path)
    )
    if spec is None or spec.loader is None:
        return None
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"  ERROR importing {script_path.name}: {e}")
        return None


def run_attack_function(script_path: Path, ciphertext: str, **params):
    """Import a script and call its attack() function.

    Returns list of (score, plaintext, method_description) tuples,
    or None if the script has no attack() or it fails.
    """
    module = load_attack_module(script_path)
    if module is None:
        return None

    attack_fn = getattr(module, "attack", None)
    if attack_fn is None:
        return None

    try:
        results = attack_fn(ciphertext, **params)
        # Validate return type
        if not isinstance(results, list):
            print(f"  WARN {script_path.name}: attack() returned {type(results)}, expected list")
            return None
        return results
    except Exception as e:
        print(f"  ERROR in {script_path.name}.attack(): {e}")
        return None


def run_legacy_subprocess(script_path: Path, timeout: int = 300) -> int:
    """Run a legacy script as a subprocess.

    Returns the exit code. Output goes to stdout/stderr.
    """
    cmd = [sys.executable, "-u", str(script_path)]
    env = {
        **__import__("os").environ,
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
    }
    try:
        result = subprocess.run(
            cmd, env=env, timeout=timeout,
            cwd=str(PROJECT_ROOT),
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT after {timeout}s: {script_path.name}")
        return -1
    except Exception as e:
        print(f"  ERROR running {script_path.name}: {e}")
        return -1


def cmd_list(args):
    """List scripts with metadata."""
    log = load_exhaustion(args.exhaustion_log)
    manifest = build_manifest(str(SCRIPTS_DIR), log)
    manifest = filter_manifest(
        manifest,
        family=args.family,
        status=args.status,
        min_score=args.min_score,
        has_attack_fn=True if args.attack_only else None,
        has_header=True if args.header_only else None,
    )
    print_manifest_table(manifest, verbose=args.verbose)


def cmd_run(args):
    """Run matching attack scripts."""
    from kryptos.kernel.constants import CT

    log = load_exhaustion(args.exhaustion_log)
    manifest = build_manifest(str(SCRIPTS_DIR), log)

    if args.id:
        # Run a single script by ID
        manifest = [e for e in manifest if e["script_id"] == args.id]
        if not manifest:
            print(f"Script '{args.id}' not found.")
            sys.exit(1)
    else:
        manifest = filter_manifest(
            manifest,
            family=args.family,
            status=args.status,
            min_score=None,  # don't pre-filter by score for running
            has_attack_fn=True if args.attack_only else None,
        )

    if not manifest:
        print("No scripts match the given filters.")
        return

    print(f"Running {len(manifest)} script(s)...\n")
    all_results = []

    for entry in manifest:
        script_id = entry["script_id"]
        # Resolve path from manifest entry (supports nested subdirectories)
        rel_path = entry.get("path", f"{script_id}.py")
        # path is relative to project root (e.g. "scripts/grille/foo.py")
        script_path = PROJECT_ROOT / rel_path
        if not script_path.exists():
            # Fallback: try flat in scripts/
            script_path = SCRIPTS_DIR / f"{script_id}.py"
        if not script_path.exists():
            print(f"  SKIP {script_id} — file not found")
            continue

        print(f"--- {script_id} ---")
        t0 = time.time()

        if entry.get("has_attack_fn"):
            # Use the standard contract
            results = run_attack_function(script_path, CT)
            elapsed = time.time() - t0

            if results:
                # Filter by min_score if specified
                if args.min_score is not None:
                    results = [(s, p, m) for s, p, m in results if s >= args.min_score]

                for score, plaintext, method in results[:args.top_n]:
                    print(f"  score={score:.1f}  method={method}")
                    if args.verbose:
                        print(f"  pt={plaintext[:60]}...")

                if results:
                    best_score = max(r[0] for r in results)
                    record_run(script_id, best_score, path=args.exhaustion_log)
                    all_results.extend(
                        (score, plaintext, method, script_id)
                        for score, plaintext, method in results
                    )

            print(f"  ({elapsed:.1f}s, {len(results) if results else 0} results)")
        else:
            # Legacy: subprocess invocation
            print(f"  [legacy subprocess mode]")
            exit_code = run_legacy_subprocess(
                script_path, timeout=args.timeout
            )
            elapsed = time.time() - t0
            print(f"  (exit={exit_code}, {elapsed:.1f}s)")

        print()

    # Final summary
    if all_results:
        all_results.sort(key=lambda x: -x[0])
        print("=" * 70)
        print(f"TOP {min(args.top_n, len(all_results))} RESULTS ACROSS ALL SCRIPTS")
        print("=" * 70)
        for score, plaintext, method, sid in all_results[:args.top_n]:
            print(f"  {score:8.1f}  {sid:<40} {method}")
            if args.verbose:
                print(f"           pt={plaintext[:60]}...")


def cmd_manifest(args):
    """Generate manifest JSON to stdout or file."""
    log = load_exhaustion(args.exhaustion_log)
    manifest = build_manifest(str(SCRIPTS_DIR), log)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"Manifest written to {args.output} ({len(manifest)} scripts)")
    else:
        json.dump(manifest, sys.stdout, indent=2)
        print()


def cmd_reconcile(args):
    """Check for mismatches between script headers and exhaustion log."""
    log = load_exhaustion(args.exhaustion_log)

    from scripts.lib.discover import discover_scripts
    header_data = {}
    for script_path in discover_scripts():
        header = parse_header(str(script_path))
        if header:
            header_data[script_path.stem] = header.to_dict()

    mismatches = reconcile(header_data, log)

    if mismatches:
        print(f"Found {len(mismatches)} mismatch(es):\n")
        for m in mismatches:
            print(f"  {m}")
        print(f"\nReminder: exhaustion_log.json is authoritative.")
    else:
        print("No mismatches found between headers and exhaustion log.")

    print(f"\nScripts with standard headers: {len(header_data)}")
    print(f"Exhaustion log entries: {len(log)}")


def cmd_exhaustion_summary(args):
    """Show exhaustion log summary."""
    log = load_exhaustion(args.exhaustion_log)

    if not log:
        print("Exhaustion log is empty.")
        return

    statuses = {}
    families = {}
    for attack_id, entry in log.items():
        st = entry.get("status", "unknown")
        statuses[st] = statuses.get(st, 0) + 1
        fam = entry.get("family", "_uncategorized")
        families[fam] = families.get(fam, 0) + 1

    print(f"Exhaustion log: {len(log)} entries\n")
    print("By status:")
    for st, count in sorted(statuses.items(), key=lambda x: -x[1]):
        print(f"  {st}: {count}")
    print("\nBy family:")
    for fam, count in sorted(families.items(), key=lambda x: -x[1]):
        print(f"  {fam}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description="K4 attack script dispatcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode selection (mutually exclusive)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="List scripts with metadata")
    mode.add_argument("--run", action="store_true", help="Run matching scripts")
    mode.add_argument("--manifest", action="store_true", help="Generate manifest JSON")
    mode.add_argument("--reconcile", action="store_true", help="Check header vs log mismatches")
    mode.add_argument("--exhaustion-summary", action="store_true", help="Summarize exhaustion log")

    # Filters
    parser.add_argument("--family", help="Filter by family (substring match)")
    parser.add_argument("--status", help="Filter by status (exhausted|active|promising)")
    parser.add_argument("--min-score", type=float, help="Minimum score threshold")
    parser.add_argument("--id", help="Run a single script by ID")

    # Run options
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout per script in seconds (default: 300)")
    parser.add_argument("--top-n", type=int, default=10,
                        help="Show top N results (default: 10)")
    parser.add_argument("--attack-only", action="store_true",
                        help="Only include scripts with attack() function")
    parser.add_argument("--header-only", action="store_true",
                        help="Only include scripts with standard headers")

    # Output
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", help="Output file (for --manifest)")
    parser.add_argument("--exhaustion-log", default=None,
                        help="Path to exhaustion_log.json (default: project root)")

    args = parser.parse_args()

    if args.list:
        cmd_list(args)
    elif args.run:
        cmd_run(args)
    elif args.manifest:
        cmd_manifest(args)
    elif args.reconcile:
        cmd_reconcile(args)
    elif args.exhaustion_summary:
        cmd_exhaustion_summary(args)


if __name__ == "__main__":
    main()
