#!/usr/bin/env python3
"""
KryptosBot Key-Split Combiner Campaign.

Tests the hypothesis that K4's encryption key is derived from multiple
independent "splits" combined following Ed Scheidt's CKM key-split-combiner
principle. E-SPLIT-00 tested 51,534 straightforward mod-26 combinations;
this campaign explores non-trivial derivation methods.

ARCHITECTURE:
    Phase A — Local compute (FREE, uses all cores):
        Key derivation chains, tableau-structural keys, positional
        key generation, installation text running keys, alphabet
        mapping keys, and transposition-aware layer splits.

    Phase B — Agent intelligence (1-3 sessions):
        Reads Phase A results, cross-references with framework,
        identifies creative follow-up investigations.

    Phase C — Orchestrated campaign (5 strategies):
        Full agent orchestrator with 5 focused strategies for
        deeper investigation of key-split hypothesis.

Usage:
    python run_split_campaign.py --local                  # Phase A only (FREE)
    python run_split_campaign.py --local --agent          # Phase A then B
    python run_split_campaign.py --full                   # Phase C: orchestrated
    python run_split_campaign.py --local --workers 28     # Override worker count
    python run_split_campaign.py --local --attack derivation  # Single attack

Token budget:
    Phase A: $0 (local compute)
    Phase B: ~$1-7.50 (1-3 agent sessions)
    Phase C: ~$5-12.50 (5 orchestrated strategies)
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
logger = logging.getLogger("kryptosbot.split_campaign")


# ---------------------------------------------------------------------------
# Phase A: Local Compute
# ---------------------------------------------------------------------------

def run_local_phase(args: argparse.Namespace) -> Path:
    """Phase A: Local compute — no tokens consumed."""
    from kryptosbot.compute import (
        run_all_split_attacks,
        run_alphabet_mapping_keys,
        run_installation_text_running_key,
        run_key_derivation_chains,
        run_positional_key_generation,
        run_tableau_row_keys,
        run_transposition_aware_splits,
    )

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("PHASE A: Key-Split Combiner — Local Compute")
    logger.info("Workers: %d | Output: %s", args.workers, output_dir)
    logger.info("=" * 60)

    if args.attack == "all":
        run_all_split_attacks(args.workers, str(output_dir))
    elif args.attack == "derivation":
        run_key_derivation_chains(
            num_workers=args.workers,
            output_file=str(output_dir / "derivation_chains.json"),
        )
    elif args.attack == "tableau":
        run_tableau_row_keys(
            num_workers=args.workers,
            output_file=str(output_dir / "tableau_keys.json"),
        )
    elif args.attack == "positional":
        run_positional_key_generation(
            num_workers=args.workers,
            output_file=str(output_dir / "positional_keys.json"),
        )
    elif args.attack == "textkey":
        run_installation_text_running_key(
            num_workers=args.workers,
            output_file=str(output_dir / "text_running_keys.json"),
        )
    elif args.attack == "alphamap":
        run_alphabet_mapping_keys(
            num_workers=args.workers,
            output_file=str(output_dir / "alphabet_mapping_keys.json"),
        )
    elif args.attack == "transplit":
        run_transposition_aware_splits(
            min_width=args.trans_min,
            max_width=args.trans_max,
            num_workers=args.workers,
            output_file=str(output_dir / "trans_aware_splits.json"),
        )

    logger.info("Phase A complete. Results in %s/", output_dir)
    return output_dir


# ---------------------------------------------------------------------------
# Phase B: Agent Intelligence
# ---------------------------------------------------------------------------

async def run_agent_phase(args: argparse.Namespace) -> None:
    """
    Phase B: Agent reads local compute results and provides creative
    analysis and next-step recommendations.
    """
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", "..")).resolve()
    results_dir = Path(args.output)

    # Collect local compute results
    result_files = list(results_dir.glob("*.json"))
    result_summary = ""
    for rf in result_files:
        try:
            data = json.loads(rf.read_text())
            if isinstance(data, dict):
                compact = {k: v for k, v in data.items()
                           if k in ("attack", "configs_tested", "total_perms",
                                    "results_above_10", "best_score", "top_20",
                                    "elapsed_seconds", "per_attack", "best_overall_score")}
                result_summary += f"\n--- {rf.name} ---\n{json.dumps(compact, indent=1)}\n"
        except Exception:
            pass

    prompt = (
        "You are KryptosBot, an expert cryptanalyst specializing in Ed Scheidt's "
        "Constructive Key Management (CKM) approach to key derivation.\n\n"
        "FIRST: Read CLAUDE.md and MEMORY.md to understand the full framework.\n"
        "Pay special attention to:\n"
        "  - Ed Scheidt's patents on key-split combiners\n"
        "  - Gillogly's statement about K4 using 'an invention by Ed Scheidt'\n"
        "  - The E-SPLIT-00 results (51,534 straightforward combinations, all noise)\n\n"
        "LOCAL COMPUTE RESULTS (Phase A, already completed):\n"
        f"{result_summary}\n\n"
        "YOUR TASK (be concise):\n"
        "1. Analyze the Phase A results. What patterns emerge? Any near-misses?\n"
        "2. Cross-reference with E-SPLIT-00's findings to understand what's NEW.\n"
        "3. Identify the 3 most promising creative extensions:\n"
        "   - Novel key derivation chains not yet tested\n"
        "   - Position-dependent functions inspired by CKM patents\n"
        "   - Self-referential key generation using sculpture text\n"
        "   - Physical/geometric key derivation methods\n"
        "4. For each recommendation, write a concrete test script or analysis.\n"
        "5. Write findings to split_agent_analysis.json\n\n"
        "KEY PRINCIPLE: Scheidt's CKM creates keys that NEVER EXIST STATICALLY.\n"
        "The key is DERIVED at decrypt time from independent components.\n"
        "What combination function could produce a key that:\n"
        "  - Satisfies Bean-EQ (key[27] == key[65])\n"
        "  - Produces English plaintext with IC > 0.055\n"
        "  - Matches all 24 crib positions\n\n"
        "Think about what a cryptographer in 1989 would consider elegant."
    )

    logger.info("=" * 60)
    logger.info("PHASE B: Agent Intelligence — Key-Split Analysis")
    logger.info("=" * 60)

    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        cwd=str(project_root),
        env={"CLAUDECODE": ""},  # Allow spawning from within Claude Code sessions
    )

    output_chunks: list[str] = []
    async for message in safe_query(prompt=prompt, options=options):
        if hasattr(message, "result"):
            output_chunks.append(str(message.result))
            print(message.result, end="", flush=True)
        elif hasattr(message, "content"):
            content = str(message.content)
            if content.strip():
                output_chunks.append(content)

    agent_output_path = results_dir / "split_agent_analysis_raw.txt"
    agent_output_path.write_text("\n".join(output_chunks))
    logger.info("Agent analysis saved to %s", agent_output_path)


# ---------------------------------------------------------------------------
# Phase C: Orchestrated Campaign (5 strategies)
# ---------------------------------------------------------------------------

# Strategy definitions for the orchestrated phase
SPLIT_STRATEGY_PROMPTS = {
    "key_derivation_chain": (
        "Task: Creative multi-step key derivation chains for K4.\n\n"
        "Background: E-SPLIT-00 tested straightforward mod-26 combinations of "
        "installation keywords. Phase A tested encrypt(A,B) chains and triple chains. "
        "Your job: go DEEPER.\n\n"
        "Ideas to explore:\n"
        "1. LFSR-based key generation seeded by keyword pairs\n"
        "2. Fibonacci-like sequences: key[i] = (key[i-a] + key[i-b]) mod 26 "
        "   where seed = keyword\n"
        "3. Iterated encryption: encrypt A with B, encrypt result with C, ...\n"
        "   More than 3 layers of nesting\n"
        "4. Key derivation using the KA tableau as a lookup table\n"
        "5. Hash-like key stretching: repeatedly apply KA-Vigenere to itself\n\n"
        "Read Phase A results first. Use the framework's scoring functions.\n"
        "Test each candidate against all 24 crib positions + Bean constraints."
    ),
    "tableau_structural_key": (
        "Task: Extract keys from the physical KA tableau structure.\n\n"
        "The Vigenere tableau on the Kryptos sculpture is a 26x26 grid of the "
        "KA alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ). Phase A tested rows, columns, "
        "diagonals, and keyword-indexed sequences.\n\n"
        "Go deeper:\n"
        "1. Spiral reads of the tableau (CW, CCW from various start positions)\n"
        "2. Knight's tour paths through the tableau\n"
        "3. Coordinate pairs from LOOMIS datasheet used as (row,col) indices\n"
        "4. The DIFFERENCE between adjacent rows as a key\n"
        "5. Tableau entries at positions spelled by CT itself (self-referential)\n"
        "6. Read the tableau using K3's transposition pattern as a guide\n\n"
        "Cross-reference with MEMORY.md for tableau-related findings."
    ),
    "positional_ckm_combiner": (
        "Task: Sophisticated position-dependent key generation functions.\n\n"
        "CKM principle: the key is NEVER stored statically. It's generated "
        "position-by-position from independent components. Phase A tested 6 "
        "basic mixing functions. Your job: design more sophisticated ones.\n\n"
        "Ideas inspired by CKM patents:\n"
        "1. LFSR with taps from keyword: polynomial defined by keyword indices\n"
        "2. Fibonacci mod 26 with keyword seeds\n"
        "3. CT-feedback: key[i] = f(key[i-1], CT[i-1]) — cipher feedback mode\n"
        "4. Alternating functions: even positions use f1, odd positions use f2\n"
        "5. Running XOR: key[i] = key[i-1] XOR source[i] mod 26\n"
        "6. Position-conditional: if i is prime, use source A; else source B\n"
        "7. Autokey variants: key[i] = f(source[i], PT[i-1]) — plaintext feedback\n\n"
        "Focus on functions that a cryptographer in 1989 could implement by hand "
        "or with a simple program. Verify all against 24 crib positions + Bean."
    ),
    "installation_text_split_key": (
        "Task: The sculpture's own text as a key component.\n\n"
        "Hypothesis: K4 is partially keyed by K1-K3 plaintext or ciphertext, "
        "creating a self-referential puzzle where you must solve K1-K3 to get "
        "K4's key. Phase A tested direct running keys with offsets.\n\n"
        "Go deeper:\n"
        "1. K3 plaintext starting at specific offsets that align with "
        "   thematic content (e.g., 'SLOWLY' = position 0)\n"
        "2. K1-K3 CT/PT interleaved as a combined running key\n"
        "3. Morse code text as a key source (VIRTUALLY INVISIBLE...)\n"
        "4. K3 PT reversed as running key\n"
        "5. K2 coordinates extracted and used as positional offsets\n"
        "6. Text from Antipodes as key (differs from Kryptos in 1 position)\n"
        "7. EAST constraint filter: check that EAST gap-9 diffs [1,25,1,23] "
        "   are satisfied for any running key candidate\n\n"
        "Use the EAST constraint as a fast filter before full crib checking."
    ),
    "transposition_substitution_split": (
        "Task: Non-obvious split assignments for trans+sub layers.\n\n"
        "Standard approach: columnar transposition + Vigenere with a keyword. "
        "But what if the key assignments are SPLIT differently?\n\n"
        "Ideas:\n"
        "1. Transposition key derived from LOOMIS datasheet numbers "
        "   (elevation, coordinates as column ordering)\n"
        "2. Substitution key from one source, transposition from another, "
        "   combined via CKM at decrypt time\n"
        "3. Variable-width transposition: different column widths for different "
        "   sections of the text (split at specific boundaries)\n"
        "4. Transposition key from KA alphabet displacement vector\n"
        "5. Route transposition with non-rectangular grids derived from coordinates\n"
        "6. Double-layer: trans1(sub(trans2(CT))) with each key from different source\n\n"
        "Phase A tested widths 5-8 with top-10 keywords. Extend to width 9-10 "
        "if time permits. Use existing _columnar_decrypt infrastructure."
    ),
}


async def run_full_campaign(args: argparse.Namespace) -> None:
    """Phase C: Orchestrated 5-strategy campaign using Agent SDK."""
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", "..")).resolve()
    results_dir = Path(args.output)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Load Phase A results if available
    phase_a_summary = ""
    summary_file = results_dir / "master_summary.json"
    if summary_file.exists():
        phase_a_summary = (
            "PHASE A LOCAL COMPUTE RESULTS:\n"
            f"{summary_file.read_text()}\n\n"
        )

    strategies = list(SPLIT_STRATEGY_PROMPTS.items())
    if args.strategy:
        strategies = [(k, v) for k, v in strategies if k == args.strategy]

    logger.info("=" * 60)
    logger.info("PHASE C: Orchestrated Key-Split Campaign")
    logger.info("Strategies: %d", len(strategies))
    logger.info("=" * 60)

    for i, (name, prompt_body) in enumerate(strategies, 1):
        logger.info("--- Strategy %d/%d: %s ---", i, len(strategies), name)

        prompt = (
            "You are KryptosBot, an expert cryptanalyst. You have access to an "
            "existing framework of 370+ scripts for attacking Kryptos K4.\n\n"
            "FIRST: Read CLAUDE.md and MEMORY.md to understand the framework.\n"
            "Read reference/kryptosfan_findings.md and reference/ed_scheidt_dossier.md "
            "for Ed Scheidt's CKM background.\n\n"
            f"{phase_a_summary}"
            f"--- STRATEGY: {name} ---\n\n"
            f"{prompt_body}\n\n"
            "IMPORTANT:\n"
            "- Import constants from kryptos.kernel.constants (never hardcode CT/cribs)\n"
            "- Use score_candidate() from kryptos.kernel.scoring.aggregate for final scoring\n"
            "- Only scores at period <= 7 are meaningful\n"
            "- Bean-EQ: key[27] == key[65] (variant-independent)\n"
            "- Write results to the split_results/ directory\n"
            "- Be concise. Focus on RESULTS, not explanation."
        )

        options = ClaudeAgentOptions(
            allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
            permission_mode="bypassPermissions",
            cwd=str(project_root),
            env={"CLAUDECODE": ""},  # Allow spawning from within Claude Code sessions
        )

        output_chunks: list[str] = []
        try:
            async for message in safe_query(prompt=prompt, options=options):
                if hasattr(message, "result"):
                    output_chunks.append(str(message.result))
                    print(message.result, end="", flush=True)
                elif hasattr(message, "content"):
                    content = str(message.content)
                    if content.strip():
                        output_chunks.append(content)
        except Exception as exc:
            logger.error("Strategy %s failed: %s", name, exc)
            output_chunks.append(f"ERROR: {exc}")

        output_path = results_dir / f"strategy_{name}.txt"
        output_path.write_text("\n".join(output_chunks))
        logger.info("Strategy %s complete → %s", name, output_path)

    logger.info("=" * 60)
    logger.info("Phase C complete. All strategy results in %s/", results_dir)
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KryptosBot Key-Split Combiner Campaign",
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
        "--full", action="store_true",
        help="Run Phase C: orchestrated 5-strategy campaign",
    )
    parser.add_argument(
        "--workers", type=int, default=28,
        help="CPU workers for local compute (default: 28)",
    )
    parser.add_argument(
        "--output", type=str, default="split_results",
        help="Output directory for results (default: split_results)",
    )
    parser.add_argument(
        "--attack", type=str, default="all",
        choices=["all", "derivation", "tableau", "positional",
                 "textkey", "alphamap", "transplit"],
        help="Which local attack to run (default: all)",
    )
    parser.add_argument(
        "--strategy", type=str, default=None,
        choices=list(SPLIT_STRATEGY_PROMPTS.keys()),
        help="Run a specific Phase C strategy only",
    )
    parser.add_argument(
        "--trans-min", type=int, default=5,
        help="Min column width for transposition-aware splits (default: 5)",
    )
    parser.add_argument(
        "--trans-max", type=int, default=8,
        help="Max column width for transposition-aware splits (default: 8)",
    )

    args = parser.parse_args()

    if not args.local and not args.agent and not args.full:
        parser.error("Specify --local, --agent, --full, or a combination")

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

    if args.full:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY required for --full mode", file=sys.stderr)
            sys.exit(1)
        asyncio.run(run_full_campaign(args))


if __name__ == "__main__":
    main()
