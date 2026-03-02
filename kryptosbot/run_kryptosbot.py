#!/usr/bin/env python3
"""
KryptosBot — Multi-agent Kryptos K4 Decipherment Engine

Entry point for running cryptanalytic campaigns from VS Code or terminal.

Usage:
    python run_kryptosbot.py                    # Full campaign (all strategies)
    python run_kryptosbot.py --disproofs        # Run disproof strategies only
    python run_kryptosbot.py --single <name>    # Run one specific strategy
    python run_kryptosbot.py --report           # Print current status report
    python run_kryptosbot.py --strategies       # List all available strategies
    python run_kryptosbot.py --workers 16       # Override worker count

Environment:
    ANTHROPIC_API_KEY   Required. Your Anthropic API key.
    KBOT_PROJECT_ROOT   Optional. Path to your existing crypto framework.
                        Defaults to current directory.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env from current directory
except ImportError:
    pass  # python-dotenv not installed — rely on shell environment

from kryptosbot.config import (
    BUILTIN_STRATEGIES,
    KryptosBotConfig,
    Strategy,
    StrategyCategory,
)
from kryptosbot.database import ResultsDB
from kryptosbot.orchestrator import Orchestrator


def setup_logging(log_dir: Path, verbose: bool = False) -> None:
    """Configure logging to both console and rotating file."""
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("kryptosbot")
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Console handler — concise
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    root_logger.addHandler(console)

    # File handler — detailed
    from logging.handlers import RotatingFileHandler
    file_handler = RotatingFileHandler(
        log_dir / "kryptosbot.log",
        maxBytes=50 * 1024 * 1024,  # 50 MB
        backupCount=10,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
    ))
    root_logger.addHandler(file_handler)


def check_api_key() -> None:
    """Verify the Anthropic API key is set before launching workers."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "ERROR: ANTHROPIC_API_KEY environment variable is not set.\n"
            "Get a key from https://platform.claude.com/ and run:\n"
            "  export ANTHROPIC_API_KEY=your-key-here\n"
            "Or set it in your VS Code .env file.",
            file=sys.stderr,
        )
        sys.exit(1)


def print_strategies() -> None:
    """Display all available strategies in a readable table."""
    from kryptosbot.framework_strategies import FRAMEWORK_STRATEGIES

    print(f"\n{'Strategy':<40} {'Category':<18} {'Pri':>3}  {'Est Min':>7}  Description")
    print("-" * 115)

    print(f"\n  Framework-Aware Strategies (use existing scripts):")
    for s in sorted(FRAMEWORK_STRATEGIES, key=lambda x: (x.priority, x.name)):
        print(
            f"  {s.name:<38} {s.category.name:<18} {s.priority:>3}  {s.estimated_minutes:>5}m  "
            f"{s.description[:45]}..."
        )

    print(f"\n  Generic Strategies (write from scratch — use for reference):")
    for s in sorted(BUILTIN_STRATEGIES, key=lambda x: (x.priority, x.name)):
        print(
            f"  {s.name:<38} {s.category.name:<18} {s.priority:>3}  {s.estimated_minutes:>5}m  "
            f"{s.description[:45]}..."
        )

    print(f"\nTotal: {len(FRAMEWORK_STRATEGIES)} framework + {len(BUILTIN_STRATEGIES)} generic\n")


def print_report(db_path: Path) -> None:
    """Print the current status report from the database."""
    if not db_path.exists():
        print("No results database found. Run a campaign first.")
        return

    db = ResultsDB(db_path)
    report = db.summary_report()

    print("\n" + "=" * 70)
    print("KryptosBot Status Report")
    print("=" * 70)
    print(f"Total hypotheses:  {report['total_hypotheses']}")
    print(f"Disproofs logged:  {report['total_disproofs']}")
    print(f"Status breakdown:  {json.dumps(report['by_status'], indent=2)}")

    if report["top_candidates"]:
        print("\nTop candidates:")
        for c in report["top_candidates"]:
            print(f"  {c['strategy']}: score={c['score']:.2f}  text={c['best_plaintext'][:50]}")

    disproof_log = db.get_disproof_log()
    if disproof_log:
        print(f"\nDisproof log ({len(disproof_log)} entries):")
        for entry in disproof_log[:20]:
            print(f"  [{entry['disproved_at'][:10]}] {entry['strategy']}: {entry['criteria'][:60]}")

    print("=" * 70 + "\n")


def _run_preflight() -> None:
    """Run the SDK preflight check and report results."""
    from kryptosbot.sdk_wrapper import preflight_check

    async def _check() -> tuple[bool, str]:
        return await preflight_check()

    print("\nRunning KryptosBot preflight check...")
    print("-" * 50)

    ok, msg = asyncio.run(_check())
    if ok:
        print("  PASS: Claude CLI found and responsive")
        print("  PASS: SDK auth check succeeded")
        print("  PASS: Ready to run campaigns")
        print("-" * 50)
        print("Result: ALL CHECKS PASSED\n")
    else:
        print(f"\n  FAIL: {msg}")
        print("-" * 50)
        print("Result: PREFLIGHT FAILED — fix the above before running a campaign\n")
        sys.exit(1)


def build_config(args: argparse.Namespace) -> KryptosBotConfig:
    """Construct config from CLI args and environment."""
    project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", ".")).resolve()

    config = KryptosBotConfig(
        max_workers=args.workers,
        project_root=project_root,
        results_db_path=project_root / "kryptosbot_results.db",
        log_dir=project_root / "logs",
        priority_cutoff=args.priority,
        repeat_disproved=args.repeat_disproved,
    )

    if args.timeout:
        config.worker_timeout_minutes = args.timeout

    return config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KryptosBot — Multi-agent K4 decipherment engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--disproofs", action="store_true",
        help="Run only disproof-category strategies",
    )
    mode.add_argument(
        "--single", type=str, metavar="STRATEGY",
        help="Run a single named strategy",
    )
    mode.add_argument(
        "--bootstrap", action="store_true",
        help="Import existing framework knowledge (run FIRST before any campaign)",
    )
    mode.add_argument(
        "--report", action="store_true",
        help="Print current status report and exit",
    )
    mode.add_argument(
        "--strategies", action="store_true",
        help="List all available strategies and exit",
    )
    mode.add_argument(
        "--preflight", action="store_true",
        help="Run SDK/CLI/auth preflight check and exit",
    )

    parser.add_argument(
        "--workers", type=int, default=28,
        help="Maximum concurrent workers (default: 28)",
    )
    parser.add_argument(
        "--priority", type=int, default=10,
        help="Only run strategies with priority <= this value (default: 10)",
    )
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Per-worker timeout in minutes (default: 120)",
    )
    parser.add_argument(
        "--repeat-disproved", action="store_true",
        help="Re-run strategies that were previously disproved",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug-level logging",
    )

    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> None:
    """Async entry point — dispatches to the appropriate run mode."""
    config = build_config(args)
    setup_logging(config.log_dir, verbose=args.verbose)
    logger = logging.getLogger("kryptosbot")

    orchestrator = Orchestrator(config)

    if args.disproofs:
        logger.info("Running disproof strategies only")
        results = await orchestrator.run_disproofs_only()
        logger.info("Disproof run complete: %d strategies executed", len(results))

    elif args.bootstrap:
        logger.info("Bootstrapping from existing framework")
        counts = await orchestrator.bootstrap_from_framework()
        logger.info(
            "Bootstrap complete — imported %d disproofs, %d promising leads, %d in-progress",
            counts["disproved"], counts["promising"], counts["in_progress"],
        )
        print(f"\nBootstrap results:")
        print(f"  Disproofs imported:   {counts['disproved']}")
        print(f"  Promising leads:      {counts['promising']}")
        print(f"  In-progress tracked:  {counts['in_progress']}")
        print(f"\nRun --report to see full status, or start a campaign.")

    elif args.single:
        logger.info("Running single strategy: %s", args.single)
        result = await orchestrator.run_single(args.single)
        logger.info(
            "Strategy '%s' complete — status: %s, score: %.2f",
            result.strategy_name, result.status.value, result.score,
        )
        if result.best_plaintext:
            logger.info("Best plaintext: %s", result.best_plaintext[:100])
        if result.error:
            logger.error("Error: %s", result.error)

    else:
        logger.info("Starting full campaign")
        report = await orchestrator.run()
        logger.info(
            "Campaign complete — %d hypotheses, %d disproofs",
            report["total_hypotheses"], report["total_disproofs"],
        )


def main() -> None:
    args = parse_args()

    # Handle non-async modes
    if args.strategies:
        print_strategies()
        return

    if args.report:
        project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", ".")).resolve()
        print_report(project_root / "kryptosbot_results.db")
        return

    if args.preflight:
        _run_preflight()
        return

    # Async modes require API key
    check_api_key()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
