"""
Framework-aware strategy definitions for KryptosBot.

DESIGN PRINCIPLE: Every agent prompt begins by reading the existing
framework's documentation (CLAUDE.md, MEMORY.md) and discovering
available scripts BEFORE attempting any analysis. Agents are
explicitly forbidden from reimplementing functionality that already
exists in the framework.

This module replaces the generic prompts in config.py with
framework-integrated versions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import (
    K4_CIPHERTEXT,
    K4_LENGTH,
    KNOWN_CRIBS,
    PRIOR_METHODS,
    Strategy,
    StrategyCategory,
)
from .database import ResultsDB


# ---------------------------------------------------------------------------
# Preamble injected into EVERY agent prompt
# ---------------------------------------------------------------------------

def build_framework_preamble(
    project_root: Path,
    db: ResultsDB | None = None,
) -> str:
    """
    Construct the preamble that orients every agent within the existing
    framework. This is the single most important piece of the system:
    it prevents agents from re-deriving what's already known.
    """
    preamble_parts = [
        # ---- Step 1: Read project documentation ----
        "CRITICAL: Before writing ANY code or performing ANY analysis, you MUST:\n"
        "1. Read CLAUDE.md (or .claude/CLAUDE.md) — this contains project conventions,\n"
        "   available tools, known findings, and instructions accumulated over weeks\n"
        "   of development.\n"
        "2. Read MEMORY.md (or .claude/MEMORY.md) — this contains session-to-session\n"
        "   state: what has been tried, what has been disproved, partial results,\n"
        "   and hypotheses under investigation.\n"
        "3. Run: find . -name '*.py' -maxdepth 2 | head -80\n"
        "   to discover the existing script inventory.\n"
        "4. Read the README or any index file that describes the framework structure.\n\n"
        "DO NOT skip these steps. The framework contains 320+ validated scripts.\n"
        "Reimplementing existing functionality wastes compute and may produce\n"
        "results inconsistent with the validated codebase.\n",

        # ---- Step 2: Use existing tools ----
        "RULES FOR CODE EXECUTION:\n"
        "- PREFER calling existing scripts over writing new code.\n"
        "- If a scoring function, cipher implementation, or statistical test\n"
        "  already exists in the framework, USE IT. Do not rewrite it.\n"
        "- If you need functionality that doesn't exist, write it in a style\n"
        "  consistent with the existing codebase (check conventions in CLAUDE.md).\n"
        "- New scripts should import from the framework's existing modules\n"
        "  where possible, not duplicate utility functions.\n"
        "- All file paths should be relative to the project root.\n",

        # ---- Step 3: K4 reference data ----
        f"REFERENCE DATA:\n"
        f"K4 Ciphertext ({K4_LENGTH} chars): {K4_CIPHERTEXT}\n"
        f"Known plaintext cribs: {KNOWN_CRIBS}\n"
        f"K1-K3 methods: {PRIOR_METHODS}\n",
    ]

    # ---- Step 4: Inject disproof ledger ----
    if db is not None:
        disproof_log = db.get_disproof_log()
        if disproof_log:
            lines = ["ALREADY DISPROVED — do NOT re-test these unless specifically asked:"]
            for entry in disproof_log:
                lines.append(
                    f"  - {entry['strategy']}: {entry['criteria']} "
                    f"(evidence: {entry['evidence'][:120]})"
                )
            preamble_parts.append("\n".join(lines))

        # Also inject promising leads
        from .config import HypothesisStatus
        promising = db.get_by_status(HypothesisStatus.PROMISING)
        if promising:
            lines = ["PROMISING LEADS from prior runs (may be worth extending):"]
            for h in promising[:10]:
                lines.append(
                    f"  - {h['strategy']}: score={h['score']:.2f}, "
                    f"plaintext={h['best_plaintext'][:40]}"
                )
            preamble_parts.append("\n".join(lines))

    return "\n\n".join(preamble_parts)


# ---------------------------------------------------------------------------
# Framework-aware strategy definitions
# ---------------------------------------------------------------------------
# Each prompt assumes the agent has already read the preamble.
# Prompts reference framework discovery rather than reimplementation.

FRAMEWORK_STRATEGIES: list[Strategy] = [

    # ---- DISCOVERY / PROFILING ----
    Strategy(
        name="framework_inventory",
        category=StrategyCategory.STATISTICAL,
        description="Inventory the existing framework: catalog all scripts, their purposes, inputs/outputs, and any recorded results.",
        prompt_template=(
            "Your first task is to thoroughly understand the existing codebase.\n\n"
            "1. Read CLAUDE.md and MEMORY.md completely.\n"
            "2. List every Python script with a one-line description of what it does.\n"
            "3. Identify which scripts have already been run and what their results were\n"
            "   (check output directories, log files, result JSON/CSV files).\n"
            "4. Identify the scoring/fitness functions available and what metrics they use.\n"
            "5. Identify any recorded disproof evidence in output files.\n"
            "6. Produce a structured inventory report as JSON with the schema:\n"
            '   {{"scripts": [{{"name": "...", "purpose": "...", "category": "...", '
            '     "has_results": true/false, "result_summary": "..."}}], '
            '    "disproofs_found": [...], "promising_leads": [...], '
            '    "scoring_functions": [...], "missing_capabilities": [...]}}\n\n'
            "Write the report to framework_inventory.json in the project root.\n"
            "This is a READ-ONLY task. Do not modify any existing files."
        ),
        priority=0,  # Always run first
        estimated_minutes=15,
        tags=("inventory", "discovery", "meta"),
    ),

    # ---- TRANSPOSITION family ----
    Strategy(
        name="columnar_transposition_framework",
        category=StrategyCategory.TRANSPOSITION,
        description="Columnar transposition using the framework's existing permutation and scoring infrastructure.",
        prompt_template=(
            "Task: Columnar transposition attack on K4.\n\n"
            "FIRST: Check the framework for existing columnar transposition scripts.\n"
            "Look for files matching: *column* *transpos* *permut*\n"
            "Also check MEMORY.md for any recorded transposition results.\n\n"
            "IF existing scripts exist:\n"
            "  - Review their parameters and results\n"
            "  - Identify any key widths or permutations NOT yet tested\n"
            "  - Run the existing scripts with any untested parameters\n"
            "  - Extend the search space only where gaps exist\n\n"
            "IF no existing scripts exist:\n"
            "  - Use the framework's scoring functions (find them first!)\n"
            "  - Implement columnar transposition for key widths 2-20\n"
            "  - Use crib-based pruning: BERLIN must land at positions 64-69\n"
            "  - Write results in the framework's standard output format\n\n"
            "Key constraint: Do NOT re-test parameter ranges that MEMORY.md or\n"
            "prior output files show have already been exhausted.\n\n"
            "Report: What was already done, what you tested, what's conclusive."
        ),
        priority=2,
        estimated_minutes=60,
        disproof_criteria="All permutations for tested key widths exhausted with no crib match.",
        tags=("transposition", "columnar", "framework-aware"),
    ),

    Strategy(
        name="route_transposition_framework",
        category=StrategyCategory.TRANSPOSITION,
        description="Route cipher variants using existing grid/matrix utilities from the framework.",
        prompt_template=(
            "Task: Route transposition attack on K4.\n\n"
            "FIRST: Search the framework for grid, matrix, spiral, or route-related scripts.\n"
            "Check MEMORY.md for any prior route cipher attempts.\n\n"
            "Test these read patterns on rectangular grids (dimensions where rows*cols >= 97):\n"
            "row-major, column-major, spiral-CW, spiral-CCW, diagonal, boustrophedon,\n"
            "and any custom patterns found in the framework.\n\n"
            "Use the framework's English scoring functions for fitness evaluation.\n"
            "Verify BERLINCLOCK at positions 64-74 for each candidate.\n\n"
            "If the framework already has route cipher results, focus on:\n"
            "  - Grid dimensions not yet tested\n"
            "  - Read patterns not yet attempted\n"
            "  - Combining route transposition with other operations"
        ),
        priority=3,
        estimated_minutes=45,
        disproof_criteria="No grid + route combination produces crib alignment.",
        tags=("transposition", "route", "grid", "framework-aware"),
    ),

    # ---- POLYALPHABETIC family ----
    Strategy(
        name="vigenere_framework",
        category=StrategyCategory.POLYALPHABETIC,
        description="Vigenère/Beaufort/variant attacks using framework's existing IC and frequency tools.",
        prompt_template=(
            "Task: Polyalphabetic cipher analysis of K4.\n\n"
            "FIRST: Search for existing Vigenère, Beaufort, IC, Kasiski scripts.\n"
            "Read MEMORY.md for prior polyalphabetic results — this is one of the\n"
            "most commonly attempted approaches and may have extensive prior work.\n\n"
            "Check what's already been done:\n"
            "  - What IC values have been computed?\n"
            "  - What key lengths have been tested?\n"
            "  - What keywords have been tried?\n"
            "  - Were Beaufort and variant Beaufort tested separately?\n\n"
            "Fill gaps only. If IC analysis exists, don't recompute — read and extend.\n"
            "If keyword lists were tried, try NEW keywords not in the prior list.\n\n"
            "Also test with the Kryptos keyed alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ)\n"
            "as the tableau — this is physically on the sculpture and likely relevant.\n\n"
            "Use framework scoring functions. Report what was pre-existing vs new."
        ),
        priority=1,
        estimated_minutes=40,
        disproof_criteria="IC flat across all periods; no keyword produces crib alignment.",
        tags=("polyalphabetic", "vigenere", "beaufort", "framework-aware"),
    ),

    Strategy(
        name="autokey_framework",
        category=StrategyCategory.POLYALPHABETIC,
        description="Autokey variants bootstrapped from known crib, using framework's crib extension tools.",
        prompt_template=(
            "Task: Autokey cipher attack using BERLINCLOCK crib as bootstrap.\n\n"
            "Check framework for existing autokey or crib-extension scripts.\n\n"
            "Approach: In autokey mode, the keystream = seed + recovered plaintext.\n"
            "We know plaintext at positions 64-74 = BERLINCLOCK.\n"
            "This lets us back-derive the seed characters that produced those positions,\n"
            "then extend decryption bidirectionally.\n\n"
            "Test both plaintext-autokey and ciphertext-autokey variants.\n"
            "Use the keyed Kryptos alphabet as well as standard alphabet.\n"
            "Try seed lengths 1-15.\n\n"
            "Use the framework's scoring pipeline for evaluating extended plaintext."
        ),
        priority=2,
        estimated_minutes=40,
        disproof_criteria="No seed produces coherent English extending from crib region.",
        tags=("polyalphabetic", "autokey", "crib-bootstrap", "framework-aware"),
    ),

    # ---- HYBRID family ----
    Strategy(
        name="hybrid_k3style_framework",
        category=StrategyCategory.HYBRID,
        description="K3-style transposition+Vigenère hybrid using framework's multi-stage pipeline.",
        prompt_template=(
            "Task: Hybrid attack modeled on K3's solution method.\n\n"
            "K3 was solved with: transposition followed by Vigenère (keyword KRYPTOS).\n"
            "K4 may use the same structure with different parameters.\n\n"
            "FIRST: Check if the framework already has a hybrid/multi-stage pipeline.\n"
            "This is one of the highest-priority attacks and may have been thoroughly\n"
            "explored. Read MEMORY.md carefully for hybrid attempt records.\n\n"
            "The approach:\n"
            "  1. Reverse columnar transposition (widths 2-15)\n"
            "  2. Apply Vigenère decryption with candidate keywords\n"
            "  3. Use BERLINCLOCK at 64-74 as a constraint to prune dramatically\n\n"
            "Keywords to test: KRYPTOS, PALIMPSEST, ABSCISSA, SANBORN, SCHEIDT,\n"
            "and any project-specific keyword lists found in the framework.\n\n"
            "Also test the REVERSE order (Vigenère first, then transposition).\n"
            "Both orders must be tested independently.\n\n"
            "Use framework scoring functions. Report gaps in parameter coverage."
        ),
        priority=1,
        estimated_minutes=90,
        disproof_criteria="No transposition×keyword combination in either order produces crib alignment.",
        tags=("hybrid", "k3-style", "framework-aware"),
    ),

    # ---- KNOWN PLAINTEXT ----
    Strategy(
        name="crib_extension_framework",
        category=StrategyCategory.KNOWN_PLAINTEXT,
        description="Bidirectional crib extension using framework's key recovery tools.",
        prompt_template=(
            "Task: Extend the known plaintext BERLINCLOCK bidirectionally.\n\n"
            "FIRST: This is likely one of the most developed areas of the framework.\n"
            "Search for crib, drag, extend, bootstrap, key-recovery scripts.\n"
            "Read all prior results before attempting anything new.\n\n"
            "For each cipher model (Vigenère, Beaufort, autokey, running key, XOR):\n"
            "  1. Compute the keystream at positions 64-74 from known plaintext\n"
            "  2. Check if the keystream has structure (repeating, autokey, dictionary)\n"
            "  3. If structured, extend it and decrypt adjacent positions\n"
            "  4. Score extended plaintext with framework scoring functions\n\n"
            "Also try: Gronsfeld, Porta, and any other cipher types in the framework.\n\n"
            "KEY QUESTION: Does the framework already have keystream analysis at\n"
            "positions 64-74? If so, what patterns were found? Build on those."
        ),
        priority=1,
        estimated_minutes=40,
        disproof_criteria="No cipher model produces a coherently extending keystream.",
        tags=("known-plaintext", "crib-extension", "framework-aware"),
    ),

    # ---- STATISTICAL PROFILING ----
    Strategy(
        name="statistical_profile_framework",
        category=StrategyCategory.STATISTICAL,
        description="Comprehensive statistical profiling — but READ existing analysis first.",
        prompt_template=(
            "Task: Statistical profiling of K4 ciphertext.\n\n"
            "CRITICAL: The framework almost certainly has existing statistical analysis.\n"
            "Search for: frequency, IoC, entropy, autocorrelation, chi-squared,\n"
            "kappa, bulge, contact chart scripts and their outputs.\n\n"
            "If existing analysis exists:\n"
            "  - Compile and validate all existing results\n"
            "  - Identify any statistical tests NOT yet performed\n"
            "  - Run only the missing tests\n"
            "  - Cross-reference results to narrow the cipher family\n\n"
            "If no existing analysis:\n"
            "  - IoC (monographic + digraphic)\n"
            "  - Shannon entropy\n"
            "  - Autocorrelation periods 1-50\n"
            "  - Kappa test\n"
            "  - Bulge test\n"
            "  - Chi-squared vs English, random, Vigenère, transposition\n"
            "  - Contact chart\n\n"
            "Produce a CONCLUSION: which cipher families are CONSISTENT with\n"
            "the statistics, and which can be RULED OUT. Reference the specific\n"
            "statistical evidence for each conclusion."
        ),
        priority=1,
        estimated_minutes=30,
        tags=("statistical", "profiling", "framework-aware"),
    ),

    # ---- DISPROOF strategies ----
    Strategy(
        name="disproof_sweep_framework",
        category=StrategyCategory.DISPROOF,
        description="Systematic disproof sweep — check framework for what's already eliminated, then fill gaps.",
        prompt_template=(
            "Task: Systematic elimination of cipher families.\n\n"
            "FIRST: Read MEMORY.md and check the framework's disproof records.\n"
            "Build a ledger of what has ALREADY been disproved with evidence.\n\n"
            "Then check which of these have NOT yet been eliminated:\n"
            "  - Caesar/ROT (25 shifts)\n"
            "  - Affine (312 keys)\n"
            "  - Simple substitution (check IoC)\n"
            "  - Playfair (statistical signature + keyword attempts)\n"
            "  - Bifid (statistical + keyword × period)\n"
            "  - Four-square\n"
            "  - ADFGVX/ADFGX\n"
            "  - Hill cipher (matrix key sizes 2×2, 3×3)\n"
            "  - Rail fence (all rail counts)\n"
            "  - Nihilist cipher\n"
            "  - Trifid\n\n"
            "For each UN-eliminated cipher family:\n"
            "  - Use existing framework scripts if available\n"
            "  - Run the exhaustive test\n"
            "  - Record evidence: what was tested, why it's eliminated\n\n"
            "Produce a complete disproof ledger as JSON:\n"
            '  {{"eliminated": [{{"cipher": "...", "evidence": "...", "date": "..."}}],\n'
            '   "not_eliminated": [{{"cipher": "...", "reason": "not yet tested"}}],\n'
            '   "still_viable": [{{"cipher": "...", "supporting_evidence": "..."}}]}}'
        ),
        priority=1,
        estimated_minutes=45,
        disproof_criteria="N/A — meta-task producing disproof inventory.",
        tags=("disproof", "systematic", "ledger", "framework-aware"),
    ),

    # ---- LATERAL / SCULPTURE-AWARE ----
    Strategy(
        name="keyed_tableau_framework",
        category=StrategyCategory.LATERAL,
        description="Kryptos sculpture tableau-based attacks using the keyed alphabet that's physically engraved.",
        prompt_template=(
            "Task: Attacks using the Kryptos sculpture's keyed Vigenère tableau.\n\n"
            "The sculpture contains a modified alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ\n"
            "(standard alphabet keyed with KRYPTOS, J omitted).\n\n"
            "Check the framework for any existing keyed-alphabet implementations.\n\n"
            "Test systematically:\n"
            "  1. Standard Vigenère with keyed tableau (exhaustive keyword search)\n"
            "  2. Beaufort with keyed tableau\n"
            "  3. Variant Beaufort with keyed tableau\n"
            "  4. Porta cipher with keyed tableau\n"
            "  5. Gronsfeld with keyed tableau\n"
            "  6. Two-square using keyed alphabet for both squares\n"
            "  7. Four-square using keyed alphabet\n\n"
            "For Vigenère variants, test keywords from the Kryptos lexicon\n"
            "AND from MEMORY.md's keyword lists.\n"
            "Verify all against BERLINCLOCK crib positions.\n\n"
            "The tableau is a PHYSICAL ARTIFACT on the sculpture. Sanborn put it\n"
            "there for a reason. If it hasn't been exhaustively tested yet, this\n"
            "is a critical gap."
        ),
        priority=1,
        estimated_minutes=60,
        disproof_criteria="No keyed-tableau variant produces crib alignment.",
        tags=("lateral", "keyed-tableau", "sculpture", "framework-aware"),
    ),

    # ---- COMPOSITION: chain existing tools ----
    Strategy(
        name="pipeline_composer",
        category=StrategyCategory.HYBRID,
        description="Compose existing framework scripts into novel multi-stage pipelines not yet tried.",
        prompt_template=(
            "Task: Discover and compose novel multi-stage decryption pipelines.\n\n"
            "This is a META-STRATEGY. Your job is creative composition, not implementation.\n\n"
            "1. Inventory all cipher operation scripts in the framework\n"
            "2. Read MEMORY.md to see which COMBINATIONS have been tried\n"
            "3. Identify novel compositions not yet attempted, for example:\n"
            "   - Keyed-alphabet Vigenère → columnar transposition\n"
            "   - Route transposition → Beaufort with keyed tableau\n"
            "   - Double transposition → Vigenère (three-stage pipeline)\n"
            "   - Any operation → reverse → different operation\n"
            "4. For each novel pipeline, execute it using EXISTING scripts\n"
            "   (call them via subprocess or import, don't rewrite)\n"
            "5. Score results and report which compositions warrant further investigation\n\n"
            "Think like a cryptanalyst who has access to a toolkit of 320 scripts.\n"
            "Your value is in creative COMBINATION, not in raw computation."
        ),
        priority=2,
        estimated_minutes=90,
        tags=("hybrid", "composition", "meta-strategy", "framework-aware"),
    ),
]


# ---------------------------------------------------------------------------
# Helper to get all strategies with framework preamble
# ---------------------------------------------------------------------------

def get_framework_strategies() -> list[Strategy]:
    """Return the framework-aware strategy library."""
    return FRAMEWORK_STRATEGIES.copy()


def build_strategy_prompt(
    strategy: Strategy,
    project_root: Path,
    db: ResultsDB | None = None,
    extra_context: str = "",
) -> str:
    """
    Assemble the complete prompt for an agent: preamble + strategy + extras.

    This is the function that should be called by the worker instead of
    strategy.render_prompt() directly.
    """
    preamble = build_framework_preamble(project_root, db)
    body = strategy.render_prompt()

    parts = [preamble, "--- STRATEGY TASK ---", body]
    if extra_context:
        parts.append(f"--- ADDITIONAL CONTEXT ---\n{extra_context}")

    return "\n\n".join(parts)
