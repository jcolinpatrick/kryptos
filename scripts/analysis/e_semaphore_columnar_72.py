#!/usr/bin/env python3
"""
Cipher: columnar_transposition
Family: analysis
Status: active
Keyspace: 3 masks x 73 delim positions x keyword columnar perms x cipher variants
Last run:
Best score:
"""
"""
E-SEMAPHORE-COLUMNAR-72: SEMAPHORE as columnar transposition key on CT72

Tests the hypothesis that K4 uses:
  1. Remove 24 nulls → CT73
  2. Remove 1 delimiter → CT72
  3. Write into 8×9 grid
  4. Read columns in SEMAPHORE alphabetical order (columnar transposition)
  5. Then decrypt with Beaufort/Vigenere using various keys

Also tests:
  - SEMAPHORE as both transposition AND substitution key
  - Other 72-compatible keywords (TELEGRAPH=9, KRYPTOS=7→72/7 not integer, etc.)
  - Double transposition: SEMAPHORE columnar then periodic substitution
  - All 73 delimiter positions
  - Reverse column read order
  - Write-by-columns, read-by-rows (inverse transposition direction)

Output: results/semaphore_columnar_72.json
Repro: PYTHONPATH=src python3 -u scripts/analysis/e_semaphore_columnar_72.py
"""

import json
import sys
import os
import time
from itertools import permutations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CONSENSUS_NULL_POSITIONS,
    KRYPTOS_ALPHABET
)
from kryptos.kernel.scoring.aggregate import score_candidate_free

TOP_MASKS = [
    [18, 19, 46, 47, 56, 62, 93],
    [18, 19, 46, 48, 56, 62, 93],
    [18, 19, 47, 48, 56, 62, 93],
]

VARIANTS = ["beaufort", "vigenere", "var_beaufort"]


def keyword_col_order(keyword):
    """Get column read order from keyword (alphabetical ordering, ties by position)."""
    indexed = [(c, i) for i, c in enumerate(keyword)]
    sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
    return [x[1] for x in sorted_idx]


def columnar_transpose(text, width, col_order):
    """Write text in rows of width, read columns in col_order."""
    n = len(text)
    nrows = (n + width - 1) // width
    # Pad if needed
    padded = text + 'X' * (nrows * width - n)

    # Write into grid (row by row)
    grid = []
    for r in range(nrows):
        grid.append(padded[r * width:(r + 1) * width])

    # Read columns in order
    result = []
    for col in col_order:
        for r in range(nrows):
            if r * width + col < n:
                result.append(grid[r][col])
    return ''.join(result)


def columnar_untranspose(text, width, col_order):
    """Undo columnar transposition: text was written by columns in col_order, restore row reading."""
    n = len(text)
    nrows = (n + width - 1) // width
    full_cols = n % width if n % width != 0 else width

    # Determine column lengths
    col_lengths = []
    # In standard columnar: columns corresponding to earlier-read positions get nrows,
    # later ones get nrows-1 if there's a partial last row
    # Actually, with col_order, the first columns in col_order get the longer columns
    col_len_map = {}
    remaining = n
    for i, col in enumerate(col_order):
        # The column at position col has nrows entries if col < (n % width) [when n%width != 0]
        # Actually, it depends on whether the last row reaches this column
        if n % width == 0:
            col_len_map[col] = nrows
        else:
            col_len_map[col] = nrows if col < (n % width) else nrows - 1

    # Read text into columns
    grid = {}
    idx = 0
    for col in col_order:
        clen = col_len_map[col]
        grid[col] = text[idx:idx + clen]
        idx += clen

    # Read row by row
    result = []
    for r in range(nrows):
        for c in range(width):
            if c in grid and r < len(grid[c]):
                result.append(grid[c][r])

    return ''.join(result[:n])


def decrypt_periodic(ct_text, key_text, variant, alphabet=ALPH):
    """Decrypt with periodic key on given alphabet."""
    ct_nums = [alphabet.index(c) for c in ct_text if c in alphabet]
    key_nums = [alphabet.index(c) for c in key_text if c in alphabet]
    mod = len(alphabet)
    klen = len(key_nums)

    pt = []
    for i, c in enumerate(ct_nums):
        k = key_nums[i % klen]
        if variant == "beaufort":
            p = (k - c) % mod
        elif variant == "vigenere":
            p = (c - k) % mod
        elif variant == "var_beaufort":
            p = (c + k) % mod
        pt.append(alphabet[p])
    return ''.join(pt)


def extract_ct(extra_nulls):
    null_mask = CONSENSUS_NULL_POSITIONS | set(extra_nulls)
    return ''.join(CT[i] for i in range(CT_LEN) if i not in null_mask)


print("=" * 70)
print("E-SEMAPHORE-COLUMNAR-72")
print("=" * 70)

t0 = time.time()
all_hits = []
best_overall = {"score": 0}

# Columnar keywords and their widths
COLUMNAR_KEYWORDS = {
    "SEMAPHORE": 9,   # 72 = 8 × 9
    "TELEGRAPH": 9,   # 72 = 8 × 9
    "CHAPPE": 6,      # 72 = 12 × 6
    "CIPHER": 6,      # 72 = 12 × 6
    "SIGNAL": 6,      # 72 = 12 × 6
    "SECRET": 6,      # 72 = 12 × 6
    "OPTICAL": 7,     # not clean but test anyway
    "TOWER": 5,       # not clean
    "MORSE": 5,       # not clean
    "SCHEIDT": 7,     # not clean
    "KRYPTOS": 7,     # not clean
    "DEFECTOR": 8,    # 72 = 9 × 8
    "ABSCISSA": 8,    # 72 = 9 × 8
    "SANBORN": 7,     # not clean
}

SUBSTITUTION_KEYS = [
    "SEMAPHORE", "KRYPTOS", "DEFECTOR", "ABSCISSA", "PALIMPSEST",
    "SEVEN", "CHART", "BERLIN", "SHADOW", "TELEGRAPH", "CHAPPE",
    "POLYBIUS", "SIGNAL", "MORSE", "OPTICAL",
]

# ══════════════════════════════════════════════════════════════════════════
# MAIN SWEEP
# ══════════════════════════════════════════════════════════════════════════

for mi, extra in enumerate(TOP_MASKS):
    ct73 = extract_ct(extra)
    print(f"\n{'=' * 70}")
    print(f"Mask {mi}: extra nulls = {extra}")
    print(f"CT73: {ct73[:50]}...")

    for delim_pos in range(73):
        ct72 = ct73[:delim_pos] + ct73[delim_pos + 1:]
        if len(ct72) != 72:
            continue

        for col_kw, width in COLUMNAR_KEYWORDS.items():
            col_order = keyword_col_order(col_kw)

            # Direction 1: text was written in rows, read by columns (undo = untranspose)
            intermediate = columnar_untranspose(ct72, width, col_order)

            # Direction 2: text was written by columns, read in rows (undo = transpose)
            intermediate_rev = columnar_transpose(ct72, width, col_order)

            for inter_text, direction in [(intermediate, "undo"), (intermediate_rev, "redo")]:
                # Test as-is with score_candidate_free
                fsb = score_candidate_free(inter_text)
                if fsb.crib_score >= 5:
                    hit = {"mask": mi, "delim": delim_pos, "col_kw": col_kw,
                           "direction": direction, "sub_kw": "none", "variant": "none",
                           "score": fsb.crib_score, "pt": inter_text[:60]}
                    all_hits.append(hit)
                    if fsb.crib_score > best_overall["score"]:
                        best_overall = hit

                # Then apply substitution cipher
                for sub_kw in SUBSTITUTION_KEYS:
                    for variant in VARIANTS:
                        for alpha in [ALPH, KRYPTOS_ALPHABET]:
                            alpha_tag = "AZ" if alpha == ALPH else "KA"
                            try:
                                pt = decrypt_periodic(inter_text, sub_kw, variant, alpha)
                            except (ValueError, IndexError):
                                continue
                            fsb = score_candidate_free(pt)
                            if fsb.crib_score >= 5:
                                hit = {"mask": mi, "delim": delim_pos,
                                       "col_kw": col_kw, "direction": direction,
                                       "sub_kw": f"{sub_kw}_{alpha_tag}", "variant": variant,
                                       "score": fsb.crib_score, "pt": pt[:60]}
                                all_hits.append(hit)
                                if fsb.crib_score > best_overall["score"]:
                                    best_overall = hit

    elapsed_mask = time.time() - t0
    print(f"  Mask {mi} done: {len(all_hits)} hits >= 5 so far ({elapsed_mask:.1f}s)")

elapsed = time.time() - t0

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'=' * 70}")
print("SUMMARY")
print("=" * 70)
print(f"  Total hits (score >= 5): {len(all_hits)}")
print(f"  Best: {best_overall}")

if all_hits:
    all_hits.sort(key=lambda h: -h["score"])
    print(f"\n  Top 20:")
    for i, h in enumerate(all_hits[:20]):
        print(f"    #{i+1}: score={h['score']} col={h['col_kw']} sub={h['sub_kw']} "
              f"var={h['variant']} delim={h['delim']} pt={h['pt'][:50]}")

score_dist = Counter(h["score"] for h in all_hits)
for s in sorted(score_dist.keys(), reverse=True):
    print(f"    score {s}: {score_dist[s]}")

verdict = "SIGNAL" if best_overall["score"] >= 18 else (
    "INTERESTING" if best_overall["score"] >= 10 else "NOISE")
print(f"\n  VERDICT: {verdict}")
print(f"  Elapsed: {elapsed:.1f}s")

# Save
os.makedirs(os.path.join(_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-SEMAPHORE-COLUMNAR-72",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "total_hits": len(all_hits),
    "best": best_overall,
    "verdict": verdict,
    "top_20": all_hits[:20],
    "elapsed": round(elapsed, 1),
}
outpath = os.path.join(_ROOT, "results", "semaphore_columnar_72.json")
with open(outpath, "w") as f:
    json.dump(artifact, f, indent=2, default=str)
print(f"  Artifact: {outpath}")
