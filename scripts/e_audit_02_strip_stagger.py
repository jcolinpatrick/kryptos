#!/usr/bin/env python3
"""E-AUDIT-02: Unequal-Strip Stagger Cipher with Per-Strip Mixed Alphabets.

[HYPOTHESIS] K4 was produced by:
1. Breaking plaintext into strips of unequal length
2. Enciphering each strip with a strip-specific keyed substitution alphabet
3. Reordering strips according to a manual permutation
4. Optionally reversing selected strips
5. Reading through the stacked geometry to emit 97 characters

This is NOT covered by existing eliminations because:
- Non-rectangular geometry (standard columnar requires rectangle)
- Per-strip substitution (not periodic, not single-alphabet)
- Strip reversal creates non-standard reading order
- Stagger offsets create non-rectangular reading paths

Uses position-FREE crib scoring (the anchored crib assumption is under test).

Test plan:
- Enumerate strip partitions of 97 into 2-6 strips
- For each partition, try all permutation orders
- For substitution: derive from keyword alphabet (KRYPTOS + variants)
- Score with free_crib + IC + ngram
"""
import json
import os
import sys
import time
from collections import Counter
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, MOD
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast, CRIB_ENE, CRIB_BC
from kryptos.kernel.scoring.ic import ic


# ── Alphabet generation ──────────────────────────────────────────────────

def keyed_alphabet(keyword: str, base: str = ALPH) -> str:
    """Generate a keyed alphabet: keyword letters first, then remaining in order."""
    seen = set()
    result = []
    for ch in keyword.upper():
        if ch in base and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in base:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return ''.join(result)


def substitution_encrypt(text: str, plain_alph: str, cipher_alph: str) -> str:
    """Simple monoalphabetic substitution: plain_alph[i] → cipher_alph[i]."""
    table = {}
    for p, c in zip(plain_alph, cipher_alph):
        table[p] = c
    return ''.join(table.get(ch, ch) for ch in text.upper())


def substitution_decrypt(text: str, plain_alph: str, cipher_alph: str) -> str:
    """Inverse substitution: cipher_alph[i] → plain_alph[i]."""
    table = {}
    for p, c in zip(plain_alph, cipher_alph):
        table[c] = p
    return ''.join(table.get(ch, ch) for ch in text.upper())


# ── Strip geometry ───────────────────────────────────────────────────────

def integer_partitions(n: int, min_parts: int, max_parts: int,
                       min_size: int = 5) -> List[Tuple[int, ...]]:
    """Generate all ordered integer partitions of n into parts.

    Each part >= min_size, number of parts in [min_parts, max_parts].
    Returns sorted tuples (canonical form) to avoid duplicates.
    """
    results = []

    def _recurse(remaining: int, parts: list, max_part_count: int):
        if remaining == 0:
            if len(parts) >= min_parts:
                results.append(tuple(sorted(parts)))
            return
        if len(parts) >= max_part_count:
            return
        # Remaining parts must each be >= min_size
        slots_left = max_part_count - len(parts)
        if remaining < min_size:
            return
        if slots_left > 0 and remaining < min_size * 1:
            return

        max_next = remaining - max(0, (1 - 1)) * min_size
        for size in range(min_size, max_next + 1):
            _recurse(remaining - size, parts + [size], max_part_count)

    _recurse(n, [], max_parts)
    # Deduplicate
    return sorted(set(results))


def partitions_of_97(n_strips_range=(2, 7), min_strip_len=8):
    """Generate strip length partitions of 97.

    Uses constrained generation: each strip must be at least min_strip_len.
    """
    results = set()
    for n in range(n_strips_range[0], n_strips_range[1] + 1):
        parts = integer_partitions(CT_LEN, n, n, min_strip_len)
        for p in parts:
            if len(p) == n:
                results.add(p)
    return sorted(results)


def split_into_strips(text: str, lengths: Tuple[int, ...]) -> List[str]:
    """Split text into strips of given lengths."""
    strips = []
    pos = 0
    for l in lengths:
        strips.append(text[pos:pos+l])
        pos += l
    return strips


def reassemble_strips(strips: List[str], perm: Tuple[int, ...],
                      reverse_flags: Tuple[bool, ...] = None) -> str:
    """Reassemble strips in permuted order, optionally reversing some."""
    result = []
    for i in perm:
        s = strips[i]
        if reverse_flags and reverse_flags[i]:
            s = s[::-1]
        result.append(s)
    return ''.join(result)


# ── Vertical reading through staggered strips ────────────────────────────

def stagger_read(strips: List[str], offsets: Tuple[int, ...] = None) -> str:
    """Read vertically through staggered strips.

    Each strip is placed at a horizontal offset. Read column-by-column
    from left to right, top to bottom within each column.
    """
    if offsets is None:
        offsets = tuple(0 for _ in strips)

    # Build a 2D grid
    max_end = max(offsets[i] + len(strips[i]) for i in range(len(strips)))
    grid = {}  # (col, row) → char

    for row, (strip, offset) in enumerate(zip(strips, offsets)):
        for col_idx, ch in enumerate(strip):
            grid[(offset + col_idx, row)] = ch

    # Read column by column, top to bottom
    result = []
    for col in range(max_end):
        for row in range(len(strips)):
            if (col, row) in grid:
                result.append(grid[(col, row)])

    return ''.join(result)


# ── Main search ──────────────────────────────────────────────────────────

def search_strip_stagger():
    print("=" * 72)
    print("E-AUDIT-02: Unequal-Strip Stagger Cipher Experiment")
    print("=" * 72)
    print()

    # Keywords for per-strip alphabets
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "IQLUSION", "SANBORN",
        "SCHEIDT", "LANGLEY", "CIA", "UNDERGROUND", "DESPARATLY",
    ]

    # Generate strip alphabets
    strip_alphabets = {}
    for kw in keywords:
        strip_alphabets[kw] = keyed_alphabet(kw)

    print(f"Keywords for strip alphabets: {len(keywords)}")

    # Phase 1: Simple strip reordering (no substitution, no stagger)
    # This tests whether pure non-rectangular transposition produces cribs
    print()
    print("Phase 1: Pure strip transposition (no substitution)")
    print("-" * 48)

    # Use a smaller range for tractability
    partitions = partitions_of_97(n_strips_range=(2, 5), min_strip_len=10)
    print(f"Strip partitions (2-5 strips, min len 10): {len(partitions)}")

    best_free_score = 0
    best_results = []
    configs_tested = 0
    t0 = time.time()

    for lengths in partitions:
        n = len(lengths)
        strips = split_into_strips(CT, lengths)

        # Try all permutations of strips
        for perm in permutations(range(n)):
            # Try with and without reversal of each strip
            for rev_flags in product([False, True], repeat=n):
                reassembled = reassemble_strips(strips, perm, rev_flags)
                configs_tested += 1

                fscore = score_free_fast(reassembled)
                if fscore > 0:
                    result = score_free(reassembled)
                    ic_val = ic(reassembled)
                    entry = {
                        "lengths": lengths,
                        "perm": perm,
                        "reversed": rev_flags,
                        "score": fscore,
                        "ic": ic_val,
                        "text_sample": reassembled[:40] + "...",
                    }
                    if result.ene_found:
                        entry["ene_offsets"] = result.ene_offsets
                    if result.bc_found:
                        entry["bc_offsets"] = result.bc_offsets
                    best_results.append(entry)
                    if fscore > best_free_score:
                        best_free_score = fscore
                        print(f"  NEW BEST: score={fscore}/24, lengths={lengths}, "
                              f"perm={perm}, rev={rev_flags}")
                        if result.ene_found:
                            print(f"    ENE at offsets: {result.ene_offsets}")
                        if result.bc_found:
                            print(f"    BC at offsets: {result.bc_offsets}")

    elapsed = time.time() - t0
    print(f"  Phase 1: {configs_tested:,} configs in {elapsed:.1f}s")
    print(f"  Best free score: {best_free_score}/24")
    print(f"  Candidates with any crib: {len(best_results)}")

    # Phase 2: Strip transposition + per-strip substitution
    print()
    print("Phase 2: Strip transposition + per-strip monoalphabetic substitution")
    print("-" * 48)

    # For tractability, focus on 2-3 strip partitions with substitution
    partitions_small = partitions_of_97(n_strips_range=(2, 3), min_strip_len=15)
    print(f"Strip partitions (2-3 strips, min len 15): {len(partitions_small)}")

    phase2_tested = 0
    phase2_best = 0
    phase2_results = []

    for lengths in partitions_small:
        n = len(lengths)
        for perm in permutations(range(n)):
            for rev_flags in product([False, True], repeat=n):
                # For each strip, try decrypting with each keyword alphabet
                for kw_combo in product(keywords[:8], repeat=n):  # Limit combos
                    # Decrypt: reverse the process
                    # CT was produced by: sub → reorder → read
                    # To recover PT: un-reorder → un-sub
                    # Step 1: un-reorder (inverse permutation)
                    ct_strips = split_into_strips(CT, lengths)

                    # The permutation maps original→output position
                    # We need to undo it: gather from perm positions
                    # If perm says strip 0 goes to position perm[0],
                    # then reading order = CT split into lengths, reordered by inverse
                    inv_perm = [0] * n
                    for i, p in enumerate(perm):
                        inv_perm[p] = i

                    # Re-split CT as if it was written in permuted order
                    # The CT strips are in the permuted order
                    perm_lengths = tuple(lengths[perm[i]] for i in range(n))
                    ct_perm_strips = split_into_strips(CT, perm_lengths)

                    # Un-reorder: map back to original strip order
                    orig_strips = [''] * n
                    for i in range(n):
                        s = ct_perm_strips[i]
                        if rev_flags[perm[i]]:
                            s = s[::-1]
                        orig_strips[perm[i]] = s

                    # Un-substitute each strip
                    pt_strips = []
                    for si, (strip, kw) in enumerate(zip(orig_strips, kw_combo)):
                        sa = strip_alphabets[kw]
                        pt_strip = substitution_decrypt(strip, ALPH, sa)
                        pt_strips.append(pt_strip)

                    plaintext = ''.join(pt_strips)
                    phase2_tested += 1

                    fscore = score_free_fast(plaintext)
                    if fscore > 0:
                        result = score_free(plaintext)
                        ic_val = ic(plaintext)
                        entry = {
                            "lengths": lengths,
                            "perm": perm,
                            "reversed": rev_flags,
                            "keywords": kw_combo,
                            "score": fscore,
                            "ic": ic_val,
                        }
                        phase2_results.append(entry)
                        if fscore > phase2_best:
                            phase2_best = fscore
                            print(f"  NEW BEST: score={fscore}/24, lengths={lengths}, "
                                  f"kws={kw_combo}")

                    if phase2_tested % 100000 == 0:
                        print(f"  ... {phase2_tested:,} configs tested, "
                              f"best={phase2_best}/24", flush=True)

    elapsed2 = time.time() - t0 - elapsed
    print(f"  Phase 2: {phase2_tested:,} configs in {elapsed2:.1f}s")
    print(f"  Best free score: {phase2_best}/24")
    print(f"  Candidates with any crib: {len(phase2_results)}")

    # Phase 3: Vertical reading through staggered strips
    print()
    print("Phase 3: Stagger read (vertical through offset strips)")
    print("-" * 48)

    # Small stagger offsets (0-5) on 2-4 strips
    partitions_stagger = partitions_of_97(n_strips_range=(2, 4), min_strip_len=12)
    print(f"Strip partitions for stagger: {len(partitions_stagger)}")

    phase3_tested = 0
    phase3_best = 0

    for lengths in partitions_stagger[:50]:  # Limit for tractability
        n = len(lengths)
        strips = split_into_strips(CT, lengths)
        max_stagger = min(5, min(lengths) - 1)

        for perm in permutations(range(n)):
            reordered = [strips[p] for p in perm]
            for offsets in product(range(max_stagger + 1), repeat=n):
                if all(o == 0 for o in offsets):
                    continue  # Skip zero offset (already tested in phase 1)
                try:
                    text = stagger_read(reordered, offsets)
                except Exception:
                    continue
                phase3_tested += 1

                fscore = score_free_fast(text)
                if fscore > 0:
                    print(f"  HIT: score={fscore}/24, lengths={lengths}, "
                          f"perm={perm}, offsets={offsets}")
                    if fscore > phase3_best:
                        phase3_best = fscore

    print(f"  Phase 3: {phase3_tested:,} configs tested")
    print(f"  Best free score: {phase3_best}/24")

    # Summary
    total_tested = configs_tested + phase2_tested + phase3_tested
    total_best = max(best_free_score, phase2_best, phase3_best)

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_tested:,}")
    print(f"Best free crib score: {total_best}/24")
    print(f"Phase 1 (pure transposition): {best_free_score}/24 from {configs_tested:,}")
    print(f"Phase 2 (trans + per-strip sub): {phase2_best}/24 from {phase2_tested:,}")
    print(f"Phase 3 (stagger read): {phase3_best}/24 from {phase3_tested:,}")
    print()

    if total_best >= 24:
        print("*** BREAKTHROUGH: Both cribs found! Investigate immediately. ***")
    elif total_best >= 13:
        print("*** SIGNAL: One full crib found. Worth deeper investigation. ***")
    elif total_best >= 11:
        print("INTERESTING: Partial crib match. May warrant expanded search.")
    else:
        print("NOISE: No crib content found. Strip stagger model does not produce cribs.")

    # Save
    os.makedirs("results/audit", exist_ok=True)
    output = {
        "experiment": "E-AUDIT-02",
        "description": "Unequal-strip stagger cipher",
        "total_configs": total_tested,
        "best_score": total_best,
        "phase1_best": best_free_score,
        "phase1_configs": configs_tested,
        "phase2_best": phase2_best,
        "phase2_configs": phase2_tested,
        "phase3_best": phase3_best,
        "phase3_configs": phase3_tested,
        "phase1_hits": best_results[:20],
        "phase2_hits": phase2_results[:20],
    }
    with open("results/audit/e_audit_02_strip_stagger.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to results/audit/e_audit_02_strip_stagger.json")


if __name__ == "__main__":
    search_strip_stagger()
