#!/usr/bin/env python3
"""
Example: Adding custom strategies to KryptosBot.

Use this as a template for strategies that leverage your existing
cryptographic framework. Import and register them with the orchestrator
before calling run().

Usage:
    python run_custom_campaign.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from kryptosbot.config import KryptosBotConfig, Strategy, StrategyCategory
from kryptosbot.orchestrator import Orchestrator


# ---------------------------------------------------------------------------
# Define custom strategies that reference YOUR existing framework
# ---------------------------------------------------------------------------

# Example: a strategy that uses scripts already in your project
FRAMEWORK_INTEGRATION = Strategy(
    name="framework_quadgram_sweep",
    category=StrategyCategory.HYBRID,
    description="Use existing framework's quadgram scorer with multi-stage pipeline.",
    prompt_template=(
        "You have access to a cryptographic analysis framework in this directory. "
        "Examine the codebase to understand the available tools (look at *.py files, "
        "CLAUDE.md, and MEMORY.md for documentation).\n\n"
        "Kryptos K4 ciphertext: {ciphertext}\n"
        "Known (0-indexed): EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73.\n\n"
        "Task: Using the EXISTING framework code:\n"
        "1. Read CLAUDE.md and MEMORY.md to understand the available tools\n"
        "2. Use the framework's scoring functions for English text quality\n"
        "3. Run a multi-stage attack: first determine likely cipher family "
        "   using statistical profiling, then apply the appropriate solver\n"
        "4. Report results using the framework's output conventions\n\n"
        "Do NOT rewrite tools that already exist — USE them."
    ),
    priority=1,
    estimated_minutes=60,
    tags=("custom", "framework-integration"),
)

# Example: a strategy targeting a specific hypothesis
DOUBLE_TRANSPOSITION = Strategy(
    name="double_columnar_transposition",
    category=StrategyCategory.TRANSPOSITION,
    description="Double columnar transposition with independent keys.",
    prompt_template=(
        "Kryptos K4 ciphertext: {ciphertext}\n"
        "Known (0-indexed): EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73.\n\n"
        "Task: Implement double columnar transposition decryption. This applies "
        "columnar transposition TWICE with independent keys. The search space "
        "is large, so use these optimizations:\n"
        "1. For the SECOND transposition (innermost), try key widths 2-10\n"
        "2. For the FIRST transposition (outermost), try key widths 2-12\n"
        "3. Use the BERLINCLOCK crib to prune: after both transpositions are "
        "   reversed, those characters must land at positions 63-73 (0-indexed)\n"
        "4. Only score candidates that pass the crib check\n\n"
        "This is computationally expensive. Implement multiprocessing with "
        "all available CPU cores. Log progress every 1000 candidates."
    ),
    priority=2,
    estimated_minutes=120,
    disproof_criteria="All width1 × width2 combinations exhausted with no crib placement.",
    tags=("transposition", "double", "brute-force"),
)

# Example: a creative / lateral strategy
CLOCK_CIPHER = Strategy(
    name="clock_arithmetic_cipher",
    category=StrategyCategory.LATERAL,
    description="The CLOCK crib may be a hint — test modular arithmetic ciphers based on clock positions.",
    prompt_template=(
        "Kryptos K4 ciphertext: {ciphertext}\n\n"
        "Sanborn confirmed 'CLOCK' appears in the plaintext. This may be a "
        "HINT about the cipher method itself. Task: Explore clock-based ciphers:\n"
        "1. Map letters to clock positions (A=1 through Z=26, mod 12 or mod 24)\n"
        "2. Test addition/subtraction with clock arithmetic\n"
        "3. Test 'clock hand' transposition: read text following hour/minute positions\n"
        "4. Consider that 'BERLIN CLOCK' is a real thing — the Mengenlehreuhr, "
        "   which displays time in set theory notation. Map K4 through the "
        "   Berlin Clock encoding scheme.\n"
        "5. Verify all candidates against the crib positions.\n\n"
        "Document your reasoning thoroughly. This is exploratory."
    ),
    priority=3,
    estimated_minutes=45,
    tags=("lateral", "clock", "modular-arithmetic", "berlin-clock"),
)

# Example: a strategy to disprove a specific popular theory
DISPROVE_BIFID = Strategy(
    name="disprove_bifid",
    category=StrategyCategory.DISPROOF,
    description="Systematically eliminate Bifid cipher with all reasonable key squares.",
    prompt_template=(
        "Kryptos K4 ciphertext: {ciphertext}\n\n"
        "Task: Test whether K4 could be a Bifid cipher.\n"
        "1. Compute statistical properties that distinguish Bifid from other ciphers\n"
        "2. Try Bifid decryption with the Kryptos keyed alphabet and period lengths 1-20\n"
        "3. Try Bifid with standard alphabet and period lengths 1-20\n"
        "4. For each, verify against BERLINCLOCK crib at positions 63-73 (0-indexed)\n"
        "5. Present clear evidence for or against the Bifid hypothesis.\n\n"
        "This is a DISPROOF task. Be thorough and conclusive."
    ),
    priority=2,
    estimated_minutes=30,
    disproof_criteria="No Polybius square + period combination produces crib match.",
    tags=("disproof", "bifid", "polybius"),
)


# ---------------------------------------------------------------------------
# Campaign runner
# ---------------------------------------------------------------------------

async def run_custom_campaign() -> None:
    config = KryptosBotConfig(
        max_workers=28,
        project_root=Path(os.environ.get("KBOT_PROJECT_ROOT", ".")),
        worker_timeout_minutes=150,
    )

    orchestrator = Orchestrator(config)

    # Register custom strategies
    orchestrator.add_strategy(FRAMEWORK_INTEGRATION)
    orchestrator.add_strategy(DOUBLE_TRANSPOSITION)
    orchestrator.add_strategy(CLOCK_CIPHER)
    orchestrator.add_strategy(DISPROVE_BIFID)

    # Run everything (built-in + custom)
    report = await orchestrator.run()

    print(f"\nCampaign complete.")
    print(f"  Hypotheses tested: {report['total_hypotheses']}")
    print(f"  Disproofs logged:  {report['total_disproofs']}")

    if report["top_candidates"]:
        print("\n  Top candidates:")
        for c in report["top_candidates"]:
            print(f"    {c['strategy']}: score={c['score']:.2f}")


if __name__ == "__main__":
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY first.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run_custom_campaign())
