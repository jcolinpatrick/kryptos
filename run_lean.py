#!/usr/bin/env python3
"""
KryptosBot Lean Runner — Token-efficient operation mode.

ARCHITECTURE:
    Phase A — Local compute (FREE, uses your CPU cores):
        Statistical profiling, exhaustive simple-cipher disproof,
        keyword sweeps, columnar transposition brute-force.
        No Agent SDK. No tokens. Pure local Python + multiprocessing.

    Phase B — Agent intelligence (TOKENS, use sparingly):
        1-3 agent sessions that READ the local compute results,
        cross-reference with the existing framework, and decide
        what to investigate next. This is where the LLM adds value:
        creative composition, pattern recognition, hypothesis
        generation — not brute-force iteration.

Usage:
    python run_lean.py --local                  # Phase A only (free)
    python run_lean.py --local --agent          # Phase A then B
    python run_lean.py --agent                  # Phase B only (reads prior results)
    python run_lean.py --local --attack columnar --workers 4
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kryptosbot.lean")


def run_local_phase(args: argparse.Namespace) -> Path:
    """Phase A: Local compute — no tokens consumed."""
    from kryptosbot.compute import (
        run_all_local_attacks,
        run_columnar_transposition,
        run_exhaustive_simple_ciphers,
        run_keyword_search,
        run_statistical_profile,
    )

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("PHASE A: Local Compute (no tokens)")
    logger.info("Workers: %d | Output: %s", args.workers, output_dir)
    logger.info("=" * 60)

    if args.attack == "all":
        run_all_local_attacks(args.workers, str(output_dir))
    elif args.attack == "stats":
        run_statistical_profile(str(output_dir / "statistical_profile.json"))
    elif args.attack == "simple":
        from kryptosbot.compute import load_quadgrams
        load_quadgrams()
        run_exhaustive_simple_ciphers(str(output_dir / "simple_ciphers.json"))
    elif args.attack == "keywords":
        run_keyword_search(
            num_workers=args.workers,
            output_file=str(output_dir / "keyword_results.json"),
        )
    elif args.attack == "columnar":
        run_columnar_transposition(
            min_width=args.col_min,
            max_width=args.col_max,
            num_workers=args.workers,
            output_file=str(output_dir / "columnar_results.json"),
        )

    logger.info("Phase A complete. Results in %s/", output_dir)
    return output_dir


async def run_agent_phase(args: argparse.Namespace) -> None:
    """
    Phase B: Agent intelligence — sparse token usage.

    Launches 1-3 agent sessions that read local compute results
    and the existing framework, then provide analysis and next steps.
    """
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", ".")).resolve()
    results_dir = Path(args.output)

    # Collect local compute results to feed the agent
    result_files = list(results_dir.glob("*.json"))
    result_summary = ""
    for rf in result_files:
        try:
            data = json.loads(rf.read_text())
            # Only send the summary, not the full data — saves tokens
            if isinstance(data, dict):
                compact = {k: v for k, v in data.items()
                           if k in ("conclusions", "status", "crib_matches",
                                    "top_20", "disproof_evidence", "per_attack",
                                    "index_of_coincidence", "autocorrelation_peaks",
                                    "caesar_disproved", "affine_disproved")}
                result_summary += f"\n--- {rf.name} ---\n{json.dumps(compact, indent=1)}\n"
        except Exception:
            pass

    prompt = (
        "You are KryptosBot, an expert cryptanalyst. You have access to an existing "
        "framework of 320+ scripts for attacking Kryptos K4.\n\n"
        "FIRST: Read CLAUDE.md and MEMORY.md to understand the framework.\n\n"
        "LOCAL COMPUTE RESULTS (already completed, no need to rerun):\n"
        f"{result_summary}\n\n"
        "YOUR TASK (be concise — minimize unnecessary file reads):\n"
        "1. Review the local compute results above.\n"
        "2. Cross-reference with what the framework has already found.\n"
        "3. Identify the 3 most promising NEXT STEPS that local compute cannot do:\n"
        "   - Novel multi-stage cipher compositions\n"
        "   - Pattern recognition in partial results\n"
        "   - Hypothesis generation based on statistical profile + sculpture context\n"
        "   - Creative lateral approaches informed by what's been eliminated\n"
        "4. For each next step, either:\n"
        "   a) Write a Python script that can be run locally with multiprocessing, OR\n"
        "   b) Execute a quick analytical check that doesn't need brute-force\n\n"
        "5. Write your findings and recommended next steps to agent_analysis.json\n\n"
        "IMPORTANT: Do NOT rerun statistical profiling, Caesar, Affine, or keyword "
        "searches — those are done. Focus on what requires REASONING, not computation."
    )

    logger.info("=" * 60)
    logger.info("PHASE B: Agent Intelligence (token-efficient)")
    logger.info("Project root: %s", project_root)
    logger.info("=" * 60)

    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        cwd=str(project_root),
    )

    output_chunks: list[str] = []
    async for message in safe_query(prompt=prompt, options=options):
        if hasattr(message, "result"):
            output_chunks.append(str(message.result))
            # Print incrementally so you can watch
            print(message.result, end="", flush=True)
        elif hasattr(message, "content"):
            content = str(message.content)
            if content.strip():
                output_chunks.append(content)

    # Save agent output
    agent_output_path = results_dir / "agent_analysis_raw.txt"
    agent_output_path.write_text("\n".join(output_chunks))
    logger.info("Agent analysis saved to %s", agent_output_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KryptosBot Lean Runner — Token-efficient operation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--local", action="store_true",
        help="Run Phase A: local compute (no tokens)",
    )
    parser.add_argument(
        "--agent", action="store_true",
        help="Run Phase B: agent intelligence (uses tokens sparingly)",
    )
    parser.add_argument(
        "--workers", type=int, default=os.cpu_count() or 4,
        help="CPU workers for local compute (default: auto-detect)",
    )
    parser.add_argument(
        "--output", type=str, default="kbot_results",
        help="Output directory for results (default: kbot_results)",
    )
    parser.add_argument(
        "--attack", type=str, default="all",
        choices=["all", "stats", "simple", "keywords", "columnar"],
        help="Which local attack to run (default: all)",
    )
    parser.add_argument(
        "--col-min", type=int, default=2,
        help="Minimum column width for columnar transposition (default: 2)",
    )
    parser.add_argument(
        "--col-max", type=int, default=12,
        help="Maximum column width for columnar transposition (default: 12)",
    )

    args = parser.parse_args()

    if not args.local and not args.agent:
        parser.error("Specify --local, --agent, or both")

    return args


def main() -> None:
    args = parse_args()

    if args.local:
        run_local_phase(args)

    if args.agent:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY required for --agent mode", file=sys.stderr)
            sys.exit(1)
        asyncio.run(run_agent_phase(args))

    if not args.local and not args.agent:
        print("Specify --local, --agent, or both. Use --help for details.")


if __name__ == "__main__":
    main()
