#!/usr/bin/env python3
"""E-W9-POLY-01: Width-9 columnar transposition + periodic Vigenère/Beaufort.

Hypothesis: K4 = keyword Vigenère applied AFTER width-9 columnar transposition.

Procedure:
  For each of the 9! = 362,880 column orderings σ:
    1. Invert the columnar transposition: intermediate = σ⁻¹(CT)
    2. At each of 24 crib positions, compute implied key value under
       Vigenère, Beaufort, and Variant Beaufort.
    3. For periods 3–12, check if implied keys at positions sharing
       the same residue (mod period) agree.
    4. Score = max positions with consistent period-class keys.
  Threshold: ≥20/24 triggers full decrypt + inspection.
"""
from __future__ import annotations

import itertools
import sys
import time
from collections import defaultdict
from typing import List, Tuple, Dict

sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD

# ── Constants ────────────────────────────────────────────────────────────────

WIDTH = 9
FULL_ROWS = CT_LEN // WIDTH        # 10 full rows
REMAINDER = CT_LEN % WIDTH          # 97 % 9 = 7 extra chars in last partial row
TOTAL_ROWS = FULL_ROWS + (1 if REMAINDER else 0)  # 11 rows

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = [ALPH_IDX[CRIB_DICT[p]] for p in CRIB_POS]
CT_VALS = [ALPH_IDX[c] for c in CT]

PERIODS = list(range(3, 13))  # 3..12


def build_columnar_perm(col_order: Tuple[int, ...], width: int, length: int) -> List[int]:
    """Build the 'scatter' permutation for columnar transposition.

    Columnar transposition writes plaintext row-by-row into a grid of
    `width` columns, then reads columns in `col_order`.

    Returns perm such that ciphertext[i] = plaintext[perm[i]].
    This is the 'gather' direction for the ciphertext.

    To INVERT (get plaintext from ciphertext), we need inv_perm where
    plaintext[i] = ciphertext[inv_perm[i]].
    """
    nrows = (length + width - 1) // width
    remainder = length % width  # columns 0..remainder-1 have nrows entries

    # Build the read-off order: columns read in col_order sequence
    perm = []
    for col in col_order:
        if remainder == 0:
            col_len = nrows
        else:
            col_len = nrows if col < remainder else nrows - 1
        for row in range(col_len):
            perm.append(row * width + col)

    return perm


def invert_perm(perm: List[int]) -> List[int]:
    """Invert a permutation: inv[perm[i]] = i."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def score_ordering(col_order: Tuple[int, ...]) -> Tuple[int, int, str, int]:
    """Score a column ordering across all cipher variants and periods.

    Returns (best_score, best_period, best_variant, col_order_index).
    """
    # Build the columnar transposition permutation
    perm = build_columnar_perm(col_order, WIDTH, CT_LEN)
    inv = invert_perm(perm)

    # Un-transpose: intermediate[i] = CT[inv[i]]
    # But we only need the values at crib positions
    # Crib positions refer to the PLAINTEXT positions.
    # If the model is: PT → Vigenère → intermediate → columnar_transpose → CT
    # Then: CT[perm_idx] came from intermediate[orig_pos]
    # So: intermediate = un-transpose(CT), meaning intermediate[i] = CT[perm[i]]
    #   wait, let's be careful.
    #
    # Columnar transposition: CT[i] = intermediate[perm[i]]  (gather)
    # So: intermediate[perm[i]] = CT[i]
    # Therefore: intermediate[j] = CT[inv_perm[j]]  where inv_perm is the inverse
    #
    # Actually let's re-derive:
    #   perm maps: ciphertext position i reads from plaintext position perm[i]
    #   So CT[i] = intermediate[perm[i]]
    #   Inverting: intermediate[j] = CT[inv[j]] where inv = invert(perm)

    # For each crib position p, the intermediate value is CT[inv[p]]
    # Then: Vigenère: key[p] = (intermediate[p] - PT[p]) mod 26
    #        Beaufort: key[p] = (intermediate[p] + PT[p]) mod 26
    #        VarBeau:  key[p] = (PT[p] - intermediate[p]) mod 26

    inter_at_cribs = [CT_VALS[inv[p]] for p in CRIB_POS]

    best_score = 0
    best_period = 0
    best_variant = ""

    for variant_name, sign_fn in [
        ("vig", lambda ct_v, pt_v: (ct_v - pt_v) % MOD),
        ("beau", lambda ct_v, pt_v: (ct_v + pt_v) % MOD),
        ("varbeau", lambda ct_v, pt_v: (pt_v - ct_v) % MOD),
    ]:
        # Compute implied key at each crib position
        keys = [sign_fn(inter_at_cribs[i], CRIB_PT[i]) for i in range(N_CRIBS)]

        for period in PERIODS:
            # Group crib positions by residue class
            residue_groups: Dict[int, List[int]] = defaultdict(list)
            for i, p in enumerate(CRIB_POS):
                residue_groups[p % period].append(i)

            # Count positions where key agrees with majority in its class
            consistent = 0
            for residue, indices in residue_groups.items():
                if len(indices) <= 1:
                    consistent += len(indices)
                    continue
                # Find the most common key value in this residue class
                key_counts: Dict[int, int] = defaultdict(int)
                for idx in indices:
                    key_counts[keys[idx]] += 1
                max_count = max(key_counts.values())
                consistent += max_count

            if consistent > best_score:
                best_score = consistent
                best_period = period
                best_variant = variant_name

    return best_score, best_period, best_variant, 0


def full_decrypt(col_order: Tuple[int, ...], period: int, variant: str) -> str:
    """Fully decrypt with the best parameters found."""
    perm = build_columnar_perm(col_order, WIDTH, CT_LEN)
    inv = invert_perm(perm)

    # Un-transpose
    intermediate = [CT_VALS[inv[j]] for j in range(CT_LEN)]

    # Extract key from crib positions
    key_at_cribs: Dict[int, int] = {}
    for i, p in enumerate(CRIB_POS):
        ct_v = intermediate[p]
        pt_v = CRIB_PT[i]
        if variant == "vig":
            k = (ct_v - pt_v) % MOD
        elif variant == "beau":
            k = (ct_v + pt_v) % MOD
        else:
            k = (pt_v - ct_v) % MOD
        key_at_cribs[p] = k

    # Build full key from residue classes
    residue_key: Dict[int, int] = {}
    for p, k in key_at_cribs.items():
        r = p % period
        if r not in residue_key:
            residue_key[r] = k
        else:
            # Use majority vote
            pass  # keep first seen for now

    # Decrypt all positions
    plaintext = []
    for j in range(CT_LEN):
        ct_v = intermediate[j]
        r = j % period
        if r in residue_key:
            k = residue_key[r]
            if variant == "vig":
                pt_v = (ct_v - k) % MOD
            elif variant == "beau":
                pt_v = (k - ct_v) % MOD
            else:
                pt_v = (ct_v + k) % MOD
            plaintext.append(chr(pt_v + ord('A')))
        else:
            plaintext.append('?')

    return ''.join(plaintext)


def main():
    print("=" * 72)
    print("E-W9-POLY-01: Width-9 columnar + periodic Vigenère/Beaufort")
    print("=" * 72)
    print(f"CT length: {CT_LEN}")
    print(f"Width: {WIDTH}, full rows: {FULL_ROWS}, remainder: {REMAINDER}")
    print(f"Total rows: {TOTAL_ROWS}")
    print(f"Crib positions ({N_CRIBS}): {CRIB_POS}")
    print(f"Periods tested: {PERIODS}")
    print(f"Cipher variants: vig, beau, varbeau")
    print(f"Total orderings: {WIDTH}! = 362,880")
    print()

    best_overall = 0
    best_results: List[Tuple[int, int, str, Tuple[int, ...]]] = []
    threshold = 20

    t0 = time.time()
    count = 0
    report_interval = 50000

    for col_order in itertools.permutations(range(WIDTH)):
        score, period, variant, _ = score_ordering(col_order)
        count += 1

        if score >= threshold:
            best_results.append((score, period, variant, col_order))
            print(f"  HIT: score={score}/24 period={period} variant={variant} "
                  f"cols={col_order}")
            pt = full_decrypt(col_order, period, variant)
            print(f"       PT: {pt}")
            print()

        if score > best_overall:
            best_overall = score
            if score < threshold:
                print(f"  New best: {score}/24 (period={period}, {variant}, "
                      f"cols={col_order})")

        if count % report_interval == 0:
            elapsed = time.time() - t0
            rate = count / elapsed
            remaining = (362880 - count) / rate
            print(f"  Progress: {count:,}/362,880 ({100*count/362880:.1f}%) "
                  f"| {rate:.0f}/s | ETA {remaining:.0f}s | best={best_overall}/24")

    elapsed = time.time() - t0

    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"Total orderings tested: {count:,}")
    print(f"Elapsed: {elapsed:.1f}s ({count/elapsed:.0f} orderings/s)")
    print(f"Best score: {best_overall}/24")
    print(f"Hits ≥{threshold}/24: {len(best_results)}")
    print()

    if best_results:
        best_results.sort(reverse=True)
        print("Top results:")
        for score, period, variant, cols in best_results[:20]:
            print(f"  score={score}/24  period={period}  variant={variant}  cols={cols}")
            pt = full_decrypt(cols, period, variant)
            print(f"  PT: {pt}")
            print()
    else:
        print(f"No orderings reached threshold {threshold}/24.")
        print(f"Maximum observed: {best_overall}/24")
        print("VERDICT: Width-9 columnar + periodic substitution → ELIMINATED")

    # Distribution analysis
    print()
    print("Score distribution (sampled from full run):")
    print(f"  Best: {best_overall}/24")
    if best_overall <= 14:
        print("  All scores within noise ceiling (≤14). No signal detected.")


if __name__ == "__main__":
    main()
