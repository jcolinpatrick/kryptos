#!/usr/bin/env python3
"""
KryptosBot Lean Runner — Unscrambling Mission.

PARADIGM (2026-03-02):
    The 97 characters carved on Kryptos are SCRAMBLED ciphertext.
    PT → simple substitution → REAL CT → SCRAMBLE → carved text.
    Mission: find the unscrambling permutation using the Cardan grille.

ARCHITECTURE:
    Phase A — Local compute (FREE, uses your 28 cores):
        Test candidate permutations against K4. For each permutation,
        unscramble the carved text, then try Vigenère/Beaufort with
        short keywords. Score with quadgrams + crib search.

    Phase B — Agent intelligence (TOKENS, use sparingly):
        One focused agent session. Given ALL context inline (no file
        reads needed). Analyzes grille data, derives candidate
        permutations, writes and runs test scripts. Capped at
        max_turns to control spend.

Usage:
    python run_lean.py --local                    # Phase A only (free)
    python run_lean.py --agent                    # Phase B only (tokens)
    python run_lean.py --local --agent            # Phase A then B
    python run_lean.py --agent --max-turns 15     # Cap agent turns
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from itertools import permutations
from math import factorial
from multiprocessing import Pool, cpu_count
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kryptosbot.lean")

# ── Constants ────────────────────────────────────────────────────────────────

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
]

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK"]


# ── Scoring ──────────────────────────────────────────────────────────────────

_QUADGRAMS: dict[str, float] | None = None


def _load_quadgrams() -> dict[str, float]:
    global _QUADGRAMS
    if _QUADGRAMS is not None:
        return _QUADGRAMS
    for p in [Path("data/english_quadgrams.json"), Path("../data/english_quadgrams.json")]:
        if p.exists():
            _QUADGRAMS = json.loads(p.read_text())
            return _QUADGRAMS
    _QUADGRAMS = {}
    return _QUADGRAMS


def score_text(text: str) -> float:
    """Quadgram log-probability score."""
    qg = _load_quadgrams()
    if not qg:
        return 0.0
    s = text.upper()
    return sum(qg.get(s[i:i+4], -10.0) for i in range(len(s) - 3))


def has_cribs(text: str) -> list[tuple[str, int]]:
    """Search for crib strings anywhere in text. Returns [(crib, position), ...]."""
    found = []
    upper = text.upper()
    for crib in CRIBS:
        idx = upper.find(crib)
        if idx >= 0:
            found.append((crib, idx))
    return found


# ── Cipher functions ─────────────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % len(key)])
        result.append(alpha[(ci - ki) % 26])
    return "".join(result)


def beau_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % len(key)])
        result.append(alpha[(ki - ci) % 26])
    return "".join(result)


# ── Permutation testing ─────────────────────────────────────────────────────

def apply_permutation(text: str, perm: list[int] | tuple[int, ...]) -> str:
    """Gather convention: output[i] = text[perm[i]]."""
    return "".join(text[p] for p in perm)


def test_unscramble(candidate_ct: str) -> dict | None:
    """Try all keywords × ciphers × alphabets on a candidate real CT.

    Returns best result dict if score is interesting, else None.
    The returned dict includes 'candidate_ct' so it can be written to real_ct.json.
    """
    best_score = -999999.0
    best = None

    for key in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(candidate_ct, key, alpha)
                except (ValueError, IndexError):
                    continue

                # Check for cribs anywhere
                crib_hits = has_cribs(pt)

                sc = score_text(pt)
                if sc > best_score:
                    best_score = sc
                    best = {
                        "candidate_ct": candidate_ct,
                        "plaintext": pt,
                        "score": sc,
                        "keyword": key,
                        "cipher": cipher_name,
                        "alphabet": alpha_name,
                        "crib_hits": crib_hits,
                    }

                # Immediate return on crib hit — this is a signal
                if crib_hits:
                    return best

    # Only return if score is notably above random
    if best and best_score > -400:
        return best
    return None


# ── Phase A: Local compute ───────────────────────────────────────────────────

def _worker_grille_index_perms(args: tuple) -> list[dict]:
    """Worker: test permutations derived from grille extract subsets."""
    method, perm_batch = args
    _load_quadgrams()
    results = []

    for perm in perm_batch:
        candidate = apply_permutation(K4_CARVED, perm)
        result = test_unscramble(candidate)
        if result:
            result["method"] = method
            result["permutation"] = list(perm)[:20]  # truncate for storage
            results.append(result)

    return results


def grille_to_numeric(extract: str, alphabet: str = KA) -> list[int]:
    """Convert grille extract letters to numeric indices in given alphabet."""
    return [alphabet.index(c) for c in extract]


def _columnar_worker(args_tuple: tuple) -> list[dict]:
    """Worker: columnar-unscramble K4, then try keyword decrypts."""
    width, perm_chunk = args_tuple
    _load_quadgrams()
    results = []

    for perm in perm_chunk:
        ncols = width
        nrows = -(-97 // ncols)
        n_long = 97 - ncols * (nrows - 1)

        col_lengths = [nrows if perm[c] < n_long else nrows - 1 for c in range(ncols)]
        cols = []
        pos = 0
        for cl in col_lengths:
            cols.append(K4_CARVED[pos:pos+cl])
            pos += cl

        ordered = [""] * ncols
        for i, col_idx in enumerate(perm):
            ordered[col_idx] = cols[i]

        unscrambled = []
        for row in range(nrows):
            for col in range(ncols):
                if row < len(ordered[col]):
                    unscrambled.append(ordered[col][row])
        candidate = "".join(unscrambled)

        result = test_unscramble(candidate)
        if result:
            result["method"] = f"columnar_unscramble:w{width}"
            result["col_key"] = list(perm)
            results.append(result)

    return results


def run_local_unscramble(args: argparse.Namespace) -> Path:
    """Phase A: Test grille-derived permutations locally."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    workers = args.workers

    logger.info("=" * 60)
    logger.info("PHASE A: Local Unscramble Compute")
    logger.info("Workers: %d | Output: %s", workers, output_dir)
    logger.info("=" * 60)

    all_results: list[dict] = []
    start = time.time()

    # ── Attack 1: Simple reading order permutations ──────────────────────
    # These are fast, no multiprocessing needed
    logger.info("Attack 1: Physical reading order permutations")

    # K4 carved in rows on the sculpture. What are the row breaks?
    # K4 is positions 768-864 in the full Kryptos text.
    # Full text rows (from e_grille_08_reconstruction.py CT_ROWS):
    # Row 26: RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSO  (starts "...UOXO..." — K4 starts mid-row)
    # Row 27: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP
    # Row 28: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
    # But K4 also spills from row 25. Let's test various row-based reorderings.

    reading_orders = {}

    # Identity (baseline)
    reading_orders["identity"] = list(range(97))

    # Reverse
    reading_orders["reverse"] = list(range(96, -1, -1))

    # Row-reversed (assuming ~31 chars per row: rows of 31, 31, 31, 4)
    for row_width in [29, 30, 31, 32, 33]:
        rows = []
        for i in range(0, 97, row_width):
            rows.append(list(range(i, min(i + row_width, 97))))

        # Reverse row order
        rev_rows = rows[::-1]
        reading_orders[f"rev_rows_w{row_width}"] = [x for row in rev_rows for x in row]

        # Boustrophedon (alternate row direction)
        boust = []
        for j, row in enumerate(rows):
            boust.extend(row if j % 2 == 0 else row[::-1])
        reading_orders[f"boust_w{row_width}"] = boust

        # Column-major (read down columns instead of across rows)
        nrows = len(rows)
        col_major = []
        for col in range(row_width):
            for row in rows:
                if col < len(row):
                    col_major.append(row[col])
        reading_orders[f"col_major_w{row_width}"] = col_major

        # Column-major reversed
        reading_orders[f"col_major_rev_w{row_width}"] = col_major[::-1]

        # Spiral (clockwise from top-left)
        spiral = []
        grid = [list(row) for row in rows]
        while grid:
            # top row left to right
            if grid:
                spiral.extend(grid.pop(0))
            # right column top to bottom
            if grid:
                for row in grid:
                    if row:
                        spiral.append(row.pop())
            # bottom row right to left
            if grid:
                spiral.extend(grid.pop()[::-1])
            # left column bottom to top
            if grid:
                for row in reversed(grid):
                    if row:
                        spiral.append(row.pop(0))
        reading_orders[f"spiral_w{row_width}"] = spiral[:97]

    # S-curve (alternating direction per row, like the physical copper plate)
    for row_width in [29, 30, 31, 32, 33]:
        rows = []
        for i in range(0, 97, row_width):
            rows.append(list(range(i, min(i + row_width, 97))))
        s_curve = []
        for j, row in enumerate(rows):
            s_curve.extend(row[::-1] if j % 2 == 1 else row)
        reading_orders[f"s_curve_w{row_width}"] = s_curve

    logger.info("  Testing %d reading orders...", len(reading_orders))

    for name, perm in reading_orders.items():
        if len(perm) != 97:
            continue  # skip malformed
        candidate = apply_permutation(K4_CARVED, perm)
        result = test_unscramble(candidate)
        if result:
            result["method"] = f"reading_order:{name}"
            result["permutation_name"] = name
            all_results.append(result)
            logger.info("  HIT: %s → score=%.1f, cribs=%s",
                        name, result["score"], result["crib_hits"])

    # ── Attack 2: Grille extract as numeric permutation ──────────────────
    logger.info("Attack 2: Grille extract → numeric index permutations")

    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        indices = grille_to_numeric(GRILLE_EXTRACT, alpha)

        # Method A: First 97 values mod 97 as permutation
        perm_raw = [v % 97 for v in indices[:97]]
        # Check if it's a valid permutation (all unique mod 97)
        if len(set(perm_raw)) == 97:
            candidate = apply_permutation(K4_CARVED, perm_raw)
            result = test_unscramble(candidate)
            if result:
                result["method"] = f"grille_mod97:{alpha_name}"
                all_results.append(result)
                logger.info("  HIT: grille_mod97:%s → score=%.1f", alpha_name, result["score"])
        else:
            logger.info("  grille_mod97:%s — not a valid permutation (%d unique of 97)",
                        alpha_name, len(set(perm_raw)))

        # Method B: Rank-order of first 97 values as permutation
        vals = indices[:97]
        # Stable sort: rank by value, break ties by position
        ranked = sorted(range(97), key=lambda i: (vals[i], i))
        candidate = apply_permutation(K4_CARVED, ranked)
        result = test_unscramble(candidate)
        if result:
            result["method"] = f"grille_rank:{alpha_name}"
            all_results.append(result)
            logger.info("  HIT: grille_rank:%s → score=%.1f", alpha_name, result["score"])

        # Method C: Inverse of rank-order
        inv_ranked = [0] * 97
        for i, r in enumerate(ranked):
            inv_ranked[r] = i
        candidate = apply_permutation(K4_CARVED, inv_ranked)
        result = test_unscramble(candidate)
        if result:
            result["method"] = f"grille_inv_rank:{alpha_name}"
            all_results.append(result)
            logger.info("  HIT: grille_inv_rank:%s → score=%.1f", alpha_name, result["score"])

    # ── Attack 3: Columnar transposition (unscramble K4, THEN decrypt) ───
    logger.info("Attack 3: Columnar unscramble + keyword decrypt (widths 2-%d)", args.col_max)

    _load_quadgrams()

    for width in range(2, min(args.col_max + 1, 11)):
        n_perms = factorial(width)
        if n_perms > 50_000_000:
            logger.info("  Width %d: %d perms — skipping (too large)", width, n_perms)
            continue

        all_perms = list(permutations(range(width)))
        chunk_size = max(1, len(all_perms) // (workers * 4))
        chunks = [(width, all_perms[i:i+chunk_size])
                  for i in range(0, len(all_perms), chunk_size)]

        logger.info("  Width %d: %d perms in %d chunks...", width, len(all_perms), len(chunks))

        with Pool(workers) as pool:
            for batch_results in pool.imap_unordered(_columnar_worker, chunks):
                for r in batch_results:
                    all_results.append(r)
                    logger.info("    HIT w%d: score=%.1f, cipher=%s, key=%s, cribs=%s",
                                width, r["score"], r["cipher"], r["keyword"], r["crib_hits"])

    # ── Save results ─────────────────────────────────────────────────────
    elapsed = time.time() - start

    # Sort by score descending
    all_results.sort(key=lambda r: -r.get("score", -99999))

    output = {
        "mission": "unscramble_k4",
        "paradigm": "carved text is scrambled ciphertext",
        "elapsed_seconds": round(elapsed, 1),
        "total_hits": len(all_results),
        "top_20": all_results[:20],
        "any_crib_found": any(r.get("crib_hits") for r in all_results),
    }

    outfile = output_dir / "unscramble_results.json"
    outfile.write_text(json.dumps(output, indent=2))
    logger.info("=" * 60)
    logger.info("Phase A complete. %d hits in %.1fs. Saved to %s",
                len(all_results), elapsed, outfile)

    if all_results:
        best = all_results[0]
        logger.info("Best: score=%.1f, method=%s, cipher=%s/%s, key=%s",
                    best["score"], best.get("method", "?"),
                    best.get("cipher", "?"), best.get("alphabet", "?"),
                    best.get("keyword", "?"))
        if best.get("crib_hits"):
            logger.info("*** CRIB FOUND: %s ***", best["crib_hits"])

        # If we found a crib hit, write real_ct.json for run_kryptosbot.py
        # Also write if score is very high (above -350, roughly English-like)
        crib_candidates = [r for r in all_results if r.get("crib_hits")]
        high_score_candidates = [r for r in all_results if r.get("score", -9999) > -350]
        signal_candidates = crib_candidates or high_score_candidates

        if signal_candidates:
            top = signal_candidates[0]
            # Reconstruct the unscrambled CT from the permutation
            perm = top.get("permutation") or top.get("col_key") or []
            method = top.get("method", "unknown")

            # We need the full permutation to reconstruct the candidate CT.
            # For columnar methods, re-derive it; for direct permutations, apply it.
            # Store the plaintext and method so run_kryptosbot.py can pick it up.
            real_ct_data = {
                "real_ct": top.get("candidate_ct", ""),
                "plaintext": top.get("plaintext", ""),
                "permutation": perm,
                "method": method,
                "score": top.get("score", 0),
                "keyword": top.get("keyword", ""),
                "cipher": top.get("cipher", ""),
                "alphabet": top.get("alphabet", ""),
                "crib_hits": top.get("crib_hits", []),
                "source": "run_lean.py Phase A",
            }

            real_ct_path = output_dir / "real_ct.json"
            real_ct_path.write_text(json.dumps(real_ct_data, indent=2))
            logger.info("=" * 60)
            logger.info("*** SIGNAL: wrote real_ct.json ***")
            logger.info("Run: python3 run_kryptosbot.py to attack the real CT")
            logger.info("=" * 60)
    else:
        logger.info("No hits above threshold.")

    logger.info("=" * 60)
    return output_dir


# ── Phase B: Agent intelligence ──────────────────────────────────────────────

AGENT_PROMPT = """\
You are KryptosBot. You have ONE mission: find how to UNSCRAMBLE the K4 carved text.

## The Paradigm
The 97 characters carved on Kryptos are SCRAMBLED ciphertext:
  PT → simple substitution → REAL CT → SCRAMBLE → carved text
The Cardan grille on the Vigenère tableau defines the unscrambling permutation.

## K4 Carved Text (scrambled)
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

## Cardan Grille Extract (106 chars, from KA tableau — NO letter T present)
HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD

## KA Alphabet
KRYPTOSABCDEFGHIJLMNQUVWXZ (keyword KRYPTOS first, then remaining letters)

## Known Cribs (positions in carved text — may be at DIFFERENT positions in real CT)
Positions 21-33: EASTNORTHEAST
Positions 63-73: BERLINCLOCK

## What to do
1. Read `memory/cardan_grille.md` (in ~/.claude/projects/-home-cpatrick-kryptos/memory/) for the binary mask and T-position analysis.
2. Devise creative ways the grille defines a permutation of 97 characters:
   - The mask hole positions as a transposition key
   - The 106 extracted letters → numeric indices → permutation
   - T-diagonal positions as position markers
   - Row-by-row hole counts or column indices
3. For EACH idea, write a Python script in the project's scripts/ directory and RUN IT.
   - Apply candidate permutation to K4 carved text
   - Try Vigenère/Beaufort with KRYPTOS, PALIMPSEST, ABSCISSA, SHADOW (AZ and KA alphabets)
   - Search for EASTNORTHEAST and BERLINCLOCK ANYWHERE in the result
   - Score with quadgrams (load from data/english_quadgrams.json)
4. Save all results to kbot_results/unscramble_analysis.json

Import constants: `sys.path.insert(0, 'src'); from kryptos.kernel.constants import CT`
Quadgrams: `json.load(open('data/english_quadgrams.json'))`

DO NOT read CLAUDE.md or explore the codebase. ALL context you need is above.
DO NOT rerun old attacks. Focus ONLY on finding the unscrambling permutation.
Write code. Run it. Report results.
"""


async def run_agent_phase(args: argparse.Namespace) -> None:
    """Phase B: One focused agent session."""
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", ".")).resolve()
    results_dir = Path(args.output)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Append local results summary if available
    prompt = AGENT_PROMPT
    local_results_path = results_dir / "unscramble_results.json"
    if local_results_path.exists():
        try:
            data = json.loads(local_results_path.read_text())
            summary = json.dumps({
                "total_hits": data.get("total_hits", 0),
                "any_crib_found": data.get("any_crib_found", False),
                "top_5": data.get("top_20", [])[:5],
            }, indent=1)
            prompt += f"\n\n## Local Compute Results (already done — do NOT repeat)\n{summary}\n"
        except Exception:
            pass

    logger.info("=" * 60)
    logger.info("PHASE B: Agent Intelligence (max_turns=%d)", args.max_turns)
    logger.info("Project root: %s", project_root)
    logger.info("=" * 60)

    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        cwd=str(project_root),
        max_turns=args.max_turns,
        env={"CLAUDECODE": ""},
    )

    output_chunks: list[str] = []
    async for message in safe_query(prompt=prompt, options=options):
        # ResultMessage — final summary at end of session
        if hasattr(message, "result") and message.result:
            output_chunks.append(str(message.result))
            print(message.result, end="", flush=True)
        # AssistantMessage — streaming content blocks (TextBlock, ToolUseBlock, etc.)
        if hasattr(message, "content") and isinstance(message.content, list):
            for block in message.content:
                if hasattr(block, "text") and block.text:
                    output_chunks.append(block.text)
                    print(block.text, flush=True)
                elif hasattr(block, "name"):
                    # ToolUseBlock — show which tool the agent is calling
                    tool_name = getattr(block, "name", "?")
                    tool_input = getattr(block, "input", {})
                    summary = str(tool_input)[:120]
                    line = f"  [tool: {tool_name}] {summary}"
                    output_chunks.append(line)
                    print(line, flush=True)

    agent_output_path = results_dir / "agent_analysis_raw.txt"
    agent_output_path.write_text("\n".join(output_chunks))
    logger.info("\nAgent analysis saved to %s", agent_output_path)


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KryptosBot Lean Runner — Unscrambling Mission",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--local", action="store_true",
                        help="Run Phase A: local unscramble compute (no tokens)")
    parser.add_argument("--agent", action="store_true",
                        help="Run Phase B: agent intelligence (uses tokens)")
    parser.add_argument("--workers", type=int, default=min(cpu_count(), 28),
                        help="CPU workers for local compute (default: all cores)")
    parser.add_argument("--output", type=str, default="kbot_results",
                        help="Output directory (default: kbot_results)")
    parser.add_argument("--col-max", type=int, default=10,
                        help="Max columnar width for unscramble (default: 10)")
    parser.add_argument("--max-turns", type=int, default=20,
                        help="Max agent turns to cap token spend (default: 20)")

    args = parser.parse_args()
    if not args.local and not args.agent:
        parser.error("Specify --local, --agent, or both")
    return args


def main() -> None:
    args = parse_args()

    if args.local:
        run_local_unscramble(args)

    if args.agent:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY required for --agent mode", file=sys.stderr)
            sys.exit(1)
        asyncio.run(run_agent_phase(args))


if __name__ == "__main__":
    main()
