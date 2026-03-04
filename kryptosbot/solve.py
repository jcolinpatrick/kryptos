#!/usr/bin/env python3
"""
KryptosBot — Unified entry point for solving Kryptos K4.

Usage:
    python solve.py                          # Default: blitz campaign (6 parallel agents)
    python solve.py compute                  # Local compute only (free, no API tokens)
    python solve.py run grille_geometry      # Run a specific strategy by name
    python solve.py run --single wildcard    # Alias for run <name>
    python solve.py reason                   # Reasoning-only agents (no code execution)
    python solve.py list                     # Show all strategies
    python solve.py preflight                # SDK/auth health check
    python solve.py report                   # Show results summary

Global flags:
    --agents N       Number of parallel agents (default: 6)
    --max-turns N    Max agentic turns per agent (default: 25)
    --budget USD     Token budget cap in USD
    --workers N      CPU workers for compute mode (default: all cores)
    --output DIR     Results directory (default: results/)
    --verbose        Enable debug logging
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import multiprocessing
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure kryptosbot package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kryptosbot.agent_runner import AgentResult, TokenTracker, run_agent_session
from kryptosbot.strategies import (
    STRATEGIES,
    Strategy,
    StrategyMode,
    build_prompt,
    get_strategies,
)

logger = logging.getLogger("kryptosbot.solve")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "results"


# ---------------------------------------------------------------------------
# Campaign runner (agent-based strategies)
# ---------------------------------------------------------------------------

async def run_campaign(
    strategies: list[Strategy],
    *,
    max_agents: int = 6,
    max_turns: int = 25,
    budget_usd: float | None = None,
    output_dir: Path = DEFAULT_OUTPUT,
    db_path: Path | None = None,
) -> list[AgentResult]:
    """Launch agent strategies with concurrency control and early termination."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    campaign_dir = output_dir / "campaigns" / timestamp
    campaign_dir.mkdir(parents=True, exist_ok=True)

    # Determine tools by mode
    agent_tools = ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]
    reasoning_tools: list[str] = []  # No tools for reasoning agents

    token_tracker = TokenTracker(budget_usd=budget_usd)
    crib_event = asyncio.Event()
    semaphore = asyncio.Semaphore(max_agents)

    # Load DB for prompt injection (optional)
    db = None
    if db_path and db_path.exists():
        try:
            from kryptosbot.database import ResultsDB
            db = ResultsDB(db_path)
        except Exception:
            pass

    async def _run_one(strategy: Strategy) -> AgentResult:
        async with semaphore:
            if crib_event.is_set():
                logger.info("Skipping %s — crib already found", strategy.name)
                return AgentResult(
                    name=strategy.name,
                    raw_output="[SKIPPED — crib found by another agent]",
                    elapsed_seconds=0,
                    crib_found=False,
                    best_score=None,
                    verdict=None,
                    raw_output_file=campaign_dir / strategy.name / "skipped.txt",
                )
            if token_tracker.is_over_budget():
                logger.warning("Skipping %s — budget exceeded", strategy.name)
                return AgentResult(
                    name=strategy.name,
                    raw_output="[SKIPPED — budget exceeded]",
                    elapsed_seconds=0,
                    crib_found=False,
                    best_score=None,
                    verdict=None,
                    raw_output_file=campaign_dir / strategy.name / "skipped.txt",
                )

            prompt = build_prompt(strategy, project_root=PROJECT_ROOT, db=db)
            tools = reasoning_tools if strategy.mode == StrategyMode.REASONING else agent_tools

            logger.info("Starting agent: %s (%s mode)", strategy.name, strategy.mode.value)

            return await run_agent_session(
                name=strategy.name,
                prompt=prompt,
                project_root=PROJECT_ROOT,
                results_dir=campaign_dir,
                max_turns=max_turns,
                crib_event=crib_event,
                allowed_tools=tools,
                token_tracker=token_tracker,
            )

    print(f"\n{'='*70}")
    print(f"  KryptosBot Campaign — {len(strategies)} strategies, {max_agents} parallel agents")
    print(f"  Output: {campaign_dir}")
    if budget_usd:
        print(f"  Budget: ${budget_usd:.2f}")
    print(f"{'='*70}\n")

    # Launch all strategies concurrently (semaphore throttles)
    tasks = [asyncio.create_task(_run_one(s), name=s.name) for s in strategies]

    # Handle SIGINT gracefully
    def _cancel_all(sig, frame):
        logger.warning("Received signal %s — cancelling agents", sig)
        for t in tasks:
            t.cancel()

    signal.signal(signal.SIGINT, _cancel_all)
    signal.signal(signal.SIGTERM, _cancel_all)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Convert exceptions to AgentResult
    final_results: list[AgentResult] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error("Strategy %s failed: %s", strategies[i].name, r)
            final_results.append(AgentResult(
                name=strategies[i].name,
                raw_output=f"ERROR: {r}",
                elapsed_seconds=0,
                crib_found=False,
                best_score=None,
                verdict=None,
                raw_output_file=campaign_dir / strategies[i].name / "error.txt",
            ))
        else:
            final_results.append(r)

    # Write campaign summary
    summary = {
        "timestamp": timestamp,
        "strategies": [s.name for s in strategies],
        "max_agents": max_agents,
        "max_turns": max_turns,
        "budget_usd": budget_usd,
        "tokens": token_tracker.summary(),
        "crib_found": any(r.crib_found for r in final_results),
        "results": [
            {
                "name": r.name,
                "elapsed": r.elapsed_seconds,
                "crib_found": r.crib_found,
                "best_score": r.best_score,
                "verdict_status": r.verdict.get("verdict_status") if r.verdict else None,
                "tokens_in": r.input_tokens,
                "tokens_out": r.output_tokens,
            }
            for r in final_results
        ],
    }
    summary_path = campaign_dir / "campaign.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    # Print summary
    print(f"\n{'='*70}")
    print(f"  CAMPAIGN COMPLETE — {token_tracker.summary()}")
    print(f"{'='*70}")
    for r in final_results:
        status = "CRIB!" if r.crib_found else ("OK" if r.best_score else "done")
        score = f"score={r.best_score}" if r.best_score else ""
        print(f"  {r.name:<25} {r.elapsed_seconds:>6.0f}s  {status:<6} {score}")
    print(f"\n  Results: {campaign_dir}")
    print(f"  Summary: {summary_path}")

    if any(r.crib_found for r in final_results):
        print(f"\n  *** CRIB HIT DETECTED — CHECK RESULTS IMMEDIATELY ***\n")

    return final_results


# ---------------------------------------------------------------------------
# Local compute runner
# ---------------------------------------------------------------------------

def run_compute(
    *,
    workers: int = 0,
    output_dir: Path = DEFAULT_OUTPUT,
    strategies: list[str] | None = None,
) -> None:
    """Run local compute strategies (no API tokens required)."""
    if workers <= 0:
        workers = multiprocessing.cpu_count() or 4

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    compute_dir = output_dir / "compute" / timestamp
    compute_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"  KryptosBot Local Compute — {workers} workers")
    print(f"  Output: {compute_dir}")
    print(f"{'='*70}\n")

    # Import compute functions
    try:
        from kryptosbot.compute import (
            run_all_local_attacks,
            run_all_split_attacks,
        )
    except ImportError as e:
        print(f"Import error: {e}")
        print("Run from ~/kryptos/ with venv activated.")
        sys.exit(1)

    start = time.monotonic()

    # Determine what to run
    run_lean = strategies is None or any(
        s in (strategies or []) for s in [
            "local_reading_orders", "local_grille_index", "local_columnar", "all"
        ]
    )
    run_split = strategies is None or any(
        s in (strategies or []) for s in [
            "local_key_derivation", "local_tableau_keys", "local_positional_keys",
            "local_text_running_key", "local_alphabet_mapping", "all"
        ]
    )

    results: dict[str, Any] = {}

    if run_lean:
        print("--- Phase: Reading Orders + Grille + Columnar ---")
        try:
            results["local_attacks"] = run_all_local_attacks(
                num_workers=workers,
                output_dir=str(compute_dir),
            )
        except Exception as e:
            logger.error("Local attacks failed: %s", e)
            results["local_attacks"] = {"error": str(e)}

    if run_split:
        print("\n--- Phase: Key Derivation + Tableau + Positional ---")
        try:
            results["split_attacks"] = run_all_split_attacks(
                num_workers=workers,
                output_dir=str(compute_dir),
            )
        except Exception as e:
            logger.error("Split attacks failed: %s", e)
            results["split_attacks"] = {"error": str(e)}

    elapsed = time.monotonic() - start

    # Write summary
    results["elapsed_seconds"] = round(elapsed, 1)
    results["workers"] = workers
    results["timestamp"] = timestamp
    summary_path = compute_dir / "compute_summary.json"
    summary_path.write_text(json.dumps(results, indent=2, default=str))

    print(f"\n{'='*70}")
    print(f"  COMPUTE COMPLETE — {elapsed:.1f}s with {workers} workers")
    print(f"  Results: {compute_dir}")
    print(f"{'='*70}\n")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def run_report(output_dir: Path = DEFAULT_OUTPUT) -> None:
    """Print a summary of results from the unified results directory."""
    campaign_dir = output_dir / "campaigns"
    compute_dir = output_dir / "compute"

    print(f"\n{'='*70}")
    print(f"  KryptosBot Results Summary")
    print(f"{'='*70}\n")

    # List campaigns
    if campaign_dir.exists():
        campaigns = sorted(campaign_dir.iterdir(), reverse=True)
        print(f"  Agent Campaigns ({len(campaigns)}):")
        for d in campaigns[:10]:
            summary_path = d / "campaign.json"
            if summary_path.exists():
                try:
                    data = json.loads(summary_path.read_text())
                    n_strats = len(data.get("strategies", []))
                    tokens = data.get("tokens", "?")
                    crib = " *** CRIB ***" if data.get("crib_found") else ""
                    print(f"    {d.name}  {n_strats} strategies  {tokens}{crib}")
                except Exception:
                    print(f"    {d.name}  (unreadable)")
            else:
                print(f"    {d.name}  (no summary)")
        if len(campaigns) > 10:
            print(f"    ... and {len(campaigns) - 10} more")
    else:
        print("  No agent campaigns found.")

    print()

    # List compute runs
    if compute_dir.exists():
        runs = sorted(compute_dir.iterdir(), reverse=True)
        print(f"  Compute Runs ({len(runs)}):")
        for d in runs[:10]:
            summary_path = d / "compute_summary.json"
            if summary_path.exists():
                try:
                    data = json.loads(summary_path.read_text())
                    elapsed = data.get("elapsed_seconds", "?")
                    workers = data.get("workers", "?")
                    print(f"    {d.name}  {elapsed}s  {workers} workers")
                except Exception:
                    print(f"    {d.name}  (unreadable)")
            else:
                print(f"    {d.name}  (no summary)")
    else:
        print("  No compute runs found.")

    print(f"\n  Results dir: {output_dir}")
    print()


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

async def run_preflight() -> bool:
    """Run SDK preflight check."""
    print("Running preflight check...")
    try:
        from kryptosbot.sdk_wrapper import preflight_check
        ok, msg = await preflight_check()
        if ok:
            print(f"  PASS: {msg}")
        else:
            print(f"  FAIL: {msg}")
        return ok
    except ImportError as e:
        print(f"  FAIL: Cannot import SDK: {e}")
        print("  Install with: pip install claude-agent-sdk")
        return False


# ---------------------------------------------------------------------------
# List strategies
# ---------------------------------------------------------------------------

def run_list(mode_filter: str | None = None) -> None:
    """Print all available strategies."""
    print(f"\n{'='*70}")
    print(f"  KryptosBot Strategy Registry — {len(STRATEGIES)} strategies")
    print(f"{'='*70}\n")

    # Group by mode
    by_mode: dict[StrategyMode, list[Strategy]] = {}
    for s in STRATEGIES.values():
        by_mode.setdefault(s.mode, []).append(s)

    mode_labels = {
        StrategyMode.AGENT: "AGENT (Claude + tools)",
        StrategyMode.REASONING: "REASONING (Claude, no tools)",
        StrategyMode.COMPUTE: "COMPUTE (local CPU, free)",
    }

    for mode in [StrategyMode.AGENT, StrategyMode.REASONING, StrategyMode.COMPUTE]:
        if mode_filter and mode.value != mode_filter:
            continue
        strats = sorted(by_mode.get(mode, []), key=lambda s: (s.priority, s.name))
        if not strats:
            continue

        print(f"  {mode_labels.get(mode, mode.value)} ({len(strats)}):")
        for s in strats:
            tags_str = f"  [{', '.join(s.tags)}]" if s.tags else ""
            print(f"    P{s.priority} {s.name:<28} {s.description[:45]}{tags_str}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solve.py",
        description="KryptosBot — Unified K4 solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global flags
    parser.add_argument("--agents", type=int, default=6,
                        help="Number of parallel agents (default: 6)")
    parser.add_argument("--max-turns", type=int, default=25,
                        help="Max agentic turns per agent (default: 25)")
    parser.add_argument("--budget", type=float, default=None,
                        help="Token budget cap in USD")
    parser.add_argument("--workers", type=int, default=0,
                        help="CPU workers for compute (default: all cores)")
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT),
                        help=f"Results directory (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")

    sub = parser.add_subparsers(dest="command")

    # Default (no subcommand) = blitz campaign
    # This is handled in main()

    # compute
    sub_compute = sub.add_parser("compute", help="Local compute only (free)")
    sub_compute.add_argument("strategies", nargs="*", default=None,
                             help="Specific compute strategies to run")

    # run
    sub_run = sub.add_parser("run", help="Run specific strategies by name")
    sub_run.add_argument("strategies", nargs="*",
                         help="Strategy names to run")
    sub_run.add_argument("--single", type=str, default=None,
                         help="Run a single strategy (alias for positional)")

    # reason
    sub.add_parser("reason", help="Reasoning-only agents (no code execution)")

    # list
    sub_list = sub.add_parser("list", help="Show all strategies")
    sub_list.add_argument("--mode", type=str, default=None,
                          choices=["agent", "reasoning", "compute"],
                          help="Filter by mode")

    # preflight
    sub.add_parser("preflight", help="SDK/auth health check")

    # report
    sub.add_parser("report", help="Show results summary")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    output_dir = Path(args.output)

    # Load dotenv if available
    try:
        from dotenv import load_dotenv
        env_file = Path(__file__).parent / ".env"
        if env_file.exists():
            load_dotenv(env_file)
    except ImportError:
        pass

    # Dispatch
    if args.command == "compute":
        run_compute(
            workers=args.workers,
            output_dir=output_dir,
            strategies=args.strategies if args.strategies else None,
        )

    elif args.command == "run":
        names = args.strategies or []
        if args.single:
            names = [args.single]
        if not names:
            parser.error("specify strategy names: solve.py run grille_geometry wildcard")

        # Resolve strategies
        strats = []
        for name in names:
            if name in STRATEGIES:
                strats.append(STRATEGIES[name])
            else:
                print(f"Unknown strategy: {name}")
                print(f"Available: {', '.join(sorted(STRATEGIES.keys()))}")
                sys.exit(1)

        asyncio.run(run_campaign(
            strats,
            max_agents=args.agents,
            max_turns=args.max_turns,
            budget_usd=args.budget,
            output_dir=output_dir,
        ))

    elif args.command == "reason":
        strats = get_strategies(mode=StrategyMode.REASONING)
        if not strats:
            print("No reasoning strategies found.")
            sys.exit(1)
        asyncio.run(run_campaign(
            strats,
            max_agents=args.agents,
            max_turns=args.max_turns,
            budget_usd=args.budget,
            output_dir=output_dir,
        ))

    elif args.command == "list":
        run_list(mode_filter=args.mode if hasattr(args, "mode") else None)

    elif args.command == "preflight":
        ok = asyncio.run(run_preflight())
        sys.exit(0 if ok else 1)

    elif args.command == "report":
        run_report(output_dir=output_dir)

    else:
        # Default: blitz campaign (all active unscramble strategies)
        strats = get_strategies(mode=StrategyMode.AGENT, tags={"active"})
        if not strats:
            strats = get_strategies(mode=StrategyMode.AGENT)
        if not strats:
            print("No agent strategies found. Use 'solve.py list' to see available strategies.")
            sys.exit(1)

        asyncio.run(run_campaign(
            strats,
            max_agents=args.agents,
            max_turns=args.max_turns,
            budget_usd=args.budget,
            output_dir=output_dir,
        ))


if __name__ == "__main__":
    main()
