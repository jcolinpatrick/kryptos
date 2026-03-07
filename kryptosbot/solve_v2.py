#!/usr/bin/env python3
"""
KryptosBot v2 — Generate-Test-Feedback loop.

Architecture:
    1. ONE Claude API call generates structured hypotheses (~$0.50-2)
    2. 28-core local compute tests them in parallel ($0)
    3. Results fed back to Claude for analysis and refinement (~$0.50-1)
    4. Auto hill-climbing on best permutations ($0)
    5. Optional batch API evaluation of top candidates (50% discount)
    6. Repeat until budget exhausted or breakthrough found

Features:
    - Conversation mode: Claude remembers its reasoning across rounds
    - Hill-climbing: auto-refine best permutations from each round
    - Batch API: cheap parallel evaluation via Haiku
    - Sandboxed generators: untrusted code runs in subprocess with timeout

Usage:
    # Default: 3 rounds, Sonnet, $10 budget, conversation mode
    python3 kryptosbot/solve_v2.py

    # Cheap test run
    python3 kryptosbot/solve_v2.py --budget 2 --rounds 1

    # Deep with Opus + conversation memory
    python3 kryptosbot/solve_v2.py --model claude-opus-4-6 --budget 30 --rounds 10

    # Disable conversation mode (independent rounds)
    python3 kryptosbot/solve_v2.py --no-conversation

    # With batch evaluation of top candidates
    python3 kryptosbot/solve_v2.py --batch-eval --budget 15

    # Free local-only (built-in reading orders + hill-climb)
    python3 kryptosbot/solve_v2.py --local-only

    # Show cost estimate
    python3 kryptosbot/solve_v2.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing as mp
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kryptosbot.hypothesis_tester import (
    CRIB_POSITIONS,
    HypothesisResult,
    run_hillclimb,
    test_all_hypotheses,
    test_hypothesis,
)

logger = logging.getLogger("kryptosbot.solve_v2")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "results"

# Hill-climbing threshold: auto-refine if score above this
HILLCLIMB_SCORE_THRESHOLD = -600.0
HILLCLIMB_ITERATIONS = 50000


# ---------------------------------------------------------------------------
# Built-in hypotheses (no API needed)
# ---------------------------------------------------------------------------

BUILTIN_HYPOTHESES = [
    {
        "name": "reading_orders_all",
        "description": "All built-in grid reading orders: row-major, col-major, reverse, boustrophedon, spiral, diagonal, stepped, grille-index",
        "type": "reading_orders_all",
        "data": {},
    },
]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_loop(
    *,
    model: str = "claude-sonnet-4-6",
    budget_usd: float = 10.0,
    max_rounds: int = 3,
    num_workers: int = 0,
    thinking_budget: int = 10000,
    output_dir: Path = DEFAULT_OUTPUT,
    local_only: bool = False,
    dry_run: bool = False,
    conversation_mode: bool = True,
    batch_eval: bool = False,
) -> None:
    """Main generate-test-feedback loop."""

    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / "v2" / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"  KryptosBot v2 — Generate-Test-Feedback Loop")
    print(f"  Model: {model}")
    print(f"  Budget: ${budget_usd:.2f}")
    print(f"  Rounds: {max_rounds}")
    print(f"  Workers: {num_workers}")
    print(f"  Thinking: {thinking_budget} tokens")
    print(f"  Conversation: {'ON' if conversation_mode else 'OFF'}")
    print(f"  Batch eval: {'ON' if batch_eval else 'OFF'}")
    print(f"  Output: {run_dir}")
    print(f"{'='*70}\n")

    if dry_run:
        est_per_round = 2.0 if "opus" in model else 0.50
        print(f"  Estimated cost per round: ~${est_per_round:.2f}")
        print(f"  Estimated total: ~${est_per_round * max_rounds:.2f}")
        print(f"  (Local compute + hill-climbing is free)")
        if batch_eval:
            print(f"  Batch eval: ~$0.10-0.50 per round (Haiku at 50% discount)")
        return

    # --- Phase 0: Test built-in hypotheses (always, free) ---
    print("--- Phase 0: Built-in hypotheses (free) ---\n")
    builtin_results = test_all_hypotheses(
        BUILTIN_HYPOTHESES,
        num_workers=num_workers,
    )
    _print_results(builtin_results)
    _save_results(run_dir / "round_0_builtin.json", builtin_results)

    # Auto hill-climb best builtin results
    builtin_results = _auto_hillclimb(builtin_results, num_workers, run_dir, 0)

    if local_only:
        print("\n  --local-only mode, skipping API rounds.")
        _print_summary(run_dir, builtin_results, None)
        _save_master_summary(run_dir, builtin_results, None, model, budget_usd, 0, local_only)
        return

    # --- API rounds ---
    from kryptosbot.api_client import KryptosAPIClient

    api_key = _load_api_key()
    if not api_key:
        print("ERROR: No ANTHROPIC_API_KEY found. Set it in environment or kryptosbot/.env")
        sys.exit(1)

    client = KryptosAPIClient(
        api_key=api_key,
        model=model,
        budget_usd=budget_usd,
        conversation_mode=conversation_mode,
    )

    all_results: list[HypothesisResult] = list(builtin_results)
    cumulative_context = _format_results_for_context(builtin_results)
    rounds_completed = 0

    for round_num in range(1, max_rounds + 1):
        if client.is_over_budget():
            print(f"\n  Budget exceeded (${client.usage.cost_usd:.2f} / ${budget_usd:.2f}). Stopping.")
            break

        print(f"\n{'='*70}")
        print(f"  Round {round_num}/{max_rounds} — {client.usage.summary()}")
        print(f"{'='*70}\n")

        # --- Generate hypotheses ---
        print("  Generating hypotheses...")
        context = f"""Previous results summary (best scores from {len(all_results)} hypotheses tested so far):

{cumulative_context}

What has NOT been tried yet or showed partial promise? Generate NEW hypotheses that explore different angles.
Focus especially on:
- The Cardan grille's physical structure (28x31 grid, key column, headers)
- The 17-cycle/8-cycle permutation structure of AZ→KA mapping
- Combinations of reading order + cycle membership masking
- Self-encrypting positions as anchor constraints
- K3's known permutation structure (2 × 168-cycle, step-7 dominant)
- Use "hillclimb" type to refine any promising permutations from prior rounds (seed_perm + fixed_positions)"""

        hypotheses = client.generate_hypotheses(
            context, thinking_budget=thinking_budget,
        )

        if not hypotheses:
            print("  No hypotheses generated. Stopping.")
            break

        print(f"  Generated {len(hypotheses)} hypotheses:")
        for h in hypotheses:
            print(f"    - {h.get('name', '?')} [{h.get('type', '?')}]: {h.get('description', '')[:55]}")

        (run_dir / f"round_{round_num}_hypotheses.json").write_text(
            json.dumps(hypotheses, indent=2)
        )

        # --- Generate scripts for generator-type hypotheses without code ---
        for i, h in enumerate(hypotheses):
            if h.get("type") == "generator" and not h.get("data", {}).get("python_code"):
                if not client.is_over_budget():
                    print(f"  Generating script for: {h['name']}...")
                    code = client.generate_test_script(h, thinking_budget=thinking_budget)
                    if code:
                        hypotheses[i]["data"]["python_code"] = code
                        script_path = run_dir / f"round_{round_num}_{h['name']}.py"
                        script_path.write_text(code)

        # --- Test hypotheses locally ---
        print(f"\n  Testing {len(hypotheses)} hypotheses on {num_workers} cores...")
        round_results = test_all_hypotheses(
            hypotheses, num_workers=num_workers,
        )
        _print_results(round_results)
        _save_results(run_dir / f"round_{round_num}_results.json", round_results)

        # --- Auto hill-climb best results ---
        round_results = _auto_hillclimb(round_results, num_workers, run_dir, round_num)

        all_results.extend(round_results)

        # --- Batch evaluation of top candidates ---
        if batch_eval and not client.is_over_budget():
            _run_batch_eval(client, round_results, run_dir, round_num)

        # --- Analyze results ---
        if not client.is_over_budget():
            print("\n  Analyzing results...")
            results_for_analysis = [
                {
                    "name": r.name,
                    "tested": r.candidates_tested,
                    "best_score": r.best_score,
                    "best_crib_hits": r.best_crib_hits,
                    "best_method": r.best_method,
                    "best_plaintext": r.best_plaintext[:40] + "..." if r.best_plaintext else "",
                    "has_perm": r.best_perm is not None,
                }
                for r in round_results
            ]
            analysis = client.analyze_results(results_for_analysis)
            print(f"\n  Analysis:\n{_indent(analysis, 4)}")
            (run_dir / f"round_{round_num}_analysis.txt").write_text(analysis)

        cumulative_context = _format_results_for_context(all_results)
        rounds_completed = round_num

        # Check for breakthrough
        if any(r.best_crib_hits >= 10 for r in round_results):
            print("\n  *** HIGH CRIB HIT COUNT DETECTED — INVESTIGATE ***")
            for r in round_results:
                if r.best_crib_hits >= 10:
                    print(f"    {r.name}: {r.best_crib_hits} crib hits, score={r.best_score}")
                    print(f"    PT: {r.best_plaintext}")
                    print(f"    Method: {r.best_method}")

    # --- Final summary ---
    _print_summary(run_dir, all_results, client)
    _save_master_summary(run_dir, all_results, client, model, budget_usd, rounds_completed, local_only)


# ---------------------------------------------------------------------------
# Auto hill-climbing
# ---------------------------------------------------------------------------

def _auto_hillclimb(
    results: list[HypothesisResult],
    num_workers: int,
    run_dir: Path,
    round_num: int,
) -> list[HypothesisResult]:
    """Auto hill-climb any result that has a best_perm and score above threshold."""
    refined = list(results)

    for r in results:
        if r.best_perm is None or r.best_score < HILLCLIMB_SCORE_THRESHOLD:
            continue

        # Parse cipher/keyword/alphabet from method string
        parts = r.best_method.split("/")
        if len(parts) != 3:
            continue

        cipher, keyword, alphabet = parts
        print(f"\n  Hill-climbing from {r.name} (score={r.best_score:.1f})...")

        hc_result = run_hillclimb(
            seed_perm=r.best_perm,
            cipher=cipher,
            keyword=keyword,
            alphabet=alphabet,
            fixed_positions=[],  # Don't fix anything — let it explore
            iterations=HILLCLIMB_ITERATIONS,
            num_workers=num_workers,
        )

        hc_name = f"{r.name}_hillclimb"
        improvement = hc_result["score"] - r.best_score
        print(
            f"  {hc_name}: score={hc_result['score']:.1f} "
            f"(delta={improvement:+.1f}), cribs={hc_result.get('crib_hits', 0)}, "
            f"{hc_result.get('elapsed_seconds', 0):.1f}s"
        )

        refined.append(HypothesisResult(
            name=hc_name,
            description=f"Hill-climb refinement of {r.name}",
            candidates_tested=hc_result.get("total_restarts", 1),
            best_score=hc_result["score"],
            best_plaintext=hc_result.get("plaintext", ""),
            best_method=hc_result.get("method", r.best_method),
            best_crib_hits=hc_result.get("crib_hits", 0),
            elapsed_seconds=hc_result.get("elapsed_seconds", 0),
            top_results=[hc_result],
            best_perm=hc_result.get("perm"),
        ))

    # Save hill-climb results if any were produced
    hc_only = refined[len(results):]
    if hc_only:
        _save_results(run_dir / f"round_{round_num}_hillclimb.json", hc_only)

    return refined


# ---------------------------------------------------------------------------
# Batch evaluation
# ---------------------------------------------------------------------------

def _run_batch_eval(
    client,
    results: list[HypothesisResult],
    run_dir: Path,
    round_num: int,
) -> None:
    """Submit top candidates for batch evaluation via Haiku."""
    candidates = []
    for r in sorted(results, key=lambda x: x.best_score, reverse=True)[:10]:
        if r.best_plaintext and r.best_score > -650:
            candidates.append({
                "plaintext": r.best_plaintext,
                "method": r.best_method,
                "score": r.best_score,
                "perm_label": r.name,
            })

    if not candidates:
        return

    print(f"\n  Submitting {len(candidates)} candidates for batch evaluation...")
    batch_results = client.evaluate_candidates_batch(candidates, timeout=300)

    if batch_results:
        print(f"  Batch evaluation complete: {len(batch_results)} results")
        for br in batch_results[:5]:
            conf = br.get("confidence", 0)
            cid = br.get("custom_id", "?")
            notes = br.get("notes", "")[:60]
            print(f"    {cid}: confidence={conf}, {notes}")
        (run_dir / f"round_{round_num}_batch_eval.json").write_text(
            json.dumps(batch_results, indent=2)
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_api_key() -> str | None:
    """Load API key from environment or .env file."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        return api_key
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def _print_results(results: list[HypothesisResult]) -> None:
    for r in results:
        flag = " ***" if r.best_crib_hits >= 5 else ""
        print(
            f"  {r.name:<30} tested={r.candidates_tested:<6} "
            f"score={r.best_score:>8.1f}  cribs={r.best_crib_hits:<3} "
            f"time={r.elapsed_seconds:.1f}s{flag}"
        )


def _save_results(path: Path, results: list[HypothesisResult]) -> None:
    data = [
        {
            "name": r.name,
            "description": r.description,
            "candidates_tested": r.candidates_tested,
            "best_score": r.best_score,
            "best_plaintext": r.best_plaintext,
            "best_method": r.best_method,
            "best_crib_hits": r.best_crib_hits,
            "elapsed_seconds": r.elapsed_seconds,
            "top_results": r.top_results[:5],
            "has_perm": r.best_perm is not None,
        }
        for r in results
    ]
    path.write_text(json.dumps(data, indent=2))


def _format_results_for_context(results: list[HypothesisResult]) -> str:
    """Format results as concise text for Claude context."""
    lines = []
    for r in sorted(results, key=lambda r: r.best_score, reverse=True)[:20]:
        perm_note = " [perm available for hillclimb]" if r.best_perm else ""
        lines.append(
            f"- {r.name}: score={r.best_score:.1f}, cribs={r.best_crib_hits}, "
            f"tested={r.candidates_tested}, method={r.best_method}{perm_note}"
        )
    return "\n".join(lines)


def _print_summary(run_dir: Path, all_results: list[HypothesisResult], client) -> None:
    print(f"\n{'='*70}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*70}")

    if client:
        print(f"  API usage: {client.usage.summary()}")

    total_tested = sum(r.candidates_tested for r in all_results)
    print(f"  Hypotheses: {len(all_results)}")
    print(f"  Total candidates tested: {total_tested:,}")

    if all_results:
        best = max(all_results, key=lambda r: r.best_score)
        best_crib = max(all_results, key=lambda r: r.best_crib_hits)
        print(f"  Best score: {best.best_score:.1f} ({best.name}, {best.best_method})")
        print(f"  Best crib hits: {best_crib.best_crib_hits} ({best_crib.name})")
        if best.best_plaintext:
            print(f"  Best PT: {best.best_plaintext[:60]}...")

    print(f"\n  Results: {run_dir}")
    print(f"{'='*70}\n")


def _save_master_summary(
    run_dir: Path,
    all_results: list[HypothesisResult],
    client,
    model: str,
    budget_usd: float,
    rounds_completed: int,
    local_only: bool,
) -> None:
    summary = {
        "timestamp": run_dir.name,
        "model": model,
        "budget_usd": budget_usd,
        "rounds_completed": rounds_completed,
        "total_hypotheses": len(all_results),
        "tokens": client.usage.summary() if client else "local only",
        "best_score": max(r.best_score for r in all_results) if all_results else -9999,
        "best_crib_hits": max(r.best_crib_hits for r in all_results) if all_results else 0,
        "top_10": [
            {
                "name": r.name,
                "score": r.best_score,
                "crib_hits": r.best_crib_hits,
                "method": r.best_method,
                "plaintext": r.best_plaintext[:50],
                "has_perm": r.best_perm is not None,
            }
            for r in sorted(all_results, key=lambda r: r.best_score, reverse=True)[:10]
        ],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))


def _indent(text: str, n: int) -> str:
    prefix = " " * n
    return "\n".join(prefix + line for line in text.splitlines())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="solve_v2.py",
        description="KryptosBot v2 — Generate-Test-Feedback loop",
    )
    parser.add_argument("--model", type=str, default="claude-sonnet-4-6",
                        choices=["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"],
                        help="Model for hypothesis generation (default: sonnet)")
    parser.add_argument("--budget", type=float, default=10.0,
                        help="API budget in USD (default: $10)")
    parser.add_argument("--rounds", type=int, default=3,
                        help="Max generate-test-feedback rounds (default: 3)")
    parser.add_argument("--workers", type=int, default=0,
                        help="CPU workers (default: all cores)")
    parser.add_argument("--thinking", type=int, default=10000,
                        help="Extended thinking budget in tokens (default: 10000)")
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT),
                        help="Results directory")
    parser.add_argument("--local-only", action="store_true",
                        help="Only run built-in hypotheses + hill-climb (no API, free)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show cost estimate without running")
    parser.add_argument("--no-conversation", action="store_true",
                        help="Disable conversation mode (independent rounds)")
    parser.add_argument("--batch-eval", action="store_true",
                        help="Enable batch API evaluation of top candidates")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    run_loop(
        model=args.model,
        budget_usd=args.budget,
        max_rounds=args.rounds,
        num_workers=args.workers,
        thinking_budget=args.thinking,
        output_dir=Path(args.output),
        local_only=args.local_only,
        dry_run=args.dry_run,
        conversation_mode=not args.no_conversation,
        batch_eval=args.batch_eval,
    )


if __name__ == "__main__":
    main()
