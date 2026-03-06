#!/usr/bin/env python3
"""Benchmark CLI — run suites, score results, generate suites.

Usage:
    PYTHONPATH=src python bench/cli.py run --suite bench/suites/tier0_smoke.jsonl
    PYTHONPATH=src python bench/cli.py run --suite bench/suites/tier0_smoke.jsonl --parallel 4 --out results/bench/
    PYTHONPATH=src python bench/cli.py score --suite bench/suites/tier0_smoke.jsonl --results results/bench/results.jsonl
    PYTHONPATH=src python bench/cli.py generate --tiers 0,1,2,3 --n 25 --seed 42 --out bench/suites/
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Ensure project root is importable when invoked directly
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))


def cmd_run(args: argparse.Namespace) -> int:
    """Execute a benchmark suite and write results."""
    from bench.io import read_suite, write_results
    from bench.runner import run_suite

    suite_path = Path(args.suite)
    if not suite_path.exists():
        print(f"Error: suite not found: {suite_path}", file=sys.stderr)
        return 1

    cases = read_suite(suite_path)
    print(f"Loaded {len(cases)} cases from {suite_path}")

    t0 = time.time()
    results = run_suite(cases, parallel=args.parallel, top_k=args.top_k)
    total_elapsed = time.time() - t0

    # Write output
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "results.jsonl"
    write_results(results, out_path)

    # Summary
    n_success = sum(1 for r in results if r.status == "success")
    n_error = sum(1 for r in results if r.status == "error")
    n_no_results = sum(1 for r in results if r.status == "no_results")
    n_match = sum(1 for r in results if r.match_plaintext)
    n_with_expected = sum(1 for c in cases if c.expected_plaintext)

    print(f"\nResults: {n_success} success, {n_error} error, {n_no_results} no_results")
    if n_with_expected:
        print(f"Accuracy: {n_match}/{n_with_expected} matched expected plaintext")
    print(f"Total time: {total_elapsed:.2f}s")
    print(f"Output: {out_path}")

    return 0 if n_error == 0 else 1


def cmd_score(args: argparse.Namespace) -> int:
    """Score benchmark results against a suite."""
    import json

    from bench.io import read_suite, read_results
    from bench.scorer import score

    suite_path = Path(args.suite)
    results_path = Path(args.results)
    for p, label in [(suite_path, "suite"), (results_path, "results")]:
        if not p.exists():
            print(f"Error: {label} not found: {p}", file=sys.stderr)
            return 1

    cases = read_suite(suite_path)
    results = read_results(results_path)
    print(f"Scoring {len(results)} results against {len(cases)} cases")

    report = score(cases, results)

    # Write outputs
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "report.json"
    with open(json_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)

    md_path = out_dir / "report.md"
    with open(md_path, "w") as f:
        f.write(report.to_markdown())

    # Print summary
    print(f"\n{report.to_markdown()}")
    print(f"Written: {json_path}")
    print(f"Written: {md_path}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bench",
        description="Kryptos benchmark runner",
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a benchmark suite")
    run_p.add_argument("--suite", required=True, help="Path to suite JSONL file")
    run_p.add_argument(
        "--parallel", type=int, default=1,
        help="Number of parallel workers (default: 1)",
    )
    run_p.add_argument(
        "--top-k", type=int, default=5,
        help="Top-K candidates to retain per case (default: 5)",
    )
    run_p.add_argument(
        "--out", default="results/bench/",
        help="Output directory (default: results/bench/)",
    )

    score_p = sub.add_parser("score", help="Score results against a suite")
    score_p.add_argument("--suite", required=True, help="Path to suite JSONL file")
    score_p.add_argument("--results", required=True, help="Path to results JSONL file")
    score_p.add_argument(
        "--out", default="results/bench/",
        help="Output directory for report.json / report.md (default: results/bench/)",
    )

    gen_p = sub.add_parser("generate", help="Generate benchmark suites")
    gen_p.add_argument(
        "--tiers", default="0,1,2,3",
        help="Comma-separated tier numbers (default: 0,1,2,3)",
    )
    gen_p.add_argument(
        "--n", type=int, default=25,
        help="Number of cases per tier (default: 25)",
    )
    gen_p.add_argument(
        "--seed", type=int, default=42,
        help="RNG seed (default: 42)",
    )
    gen_p.add_argument(
        "--out", default="bench/suites/",
        help="Output directory (default: bench/suites/)",
    )

    args = parser.parse_args()

    if args.command == "run":
        return cmd_run(args)
    if args.command == "score":
        return cmd_score(args)
    if args.command == "generate":
        from bench.generate import cmd_generate
        return cmd_generate(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
