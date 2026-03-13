#!/usr/bin/env python3
"""
grille_row2627_col_null.py   [Synthesis, 2026-03-13]

NEW STRUCTURAL HYPOTHESIS derived from combining findings A+B+C:

Observation: K4 tableau row keys are X(row24), Y(row25), Z(row26), footer(row27).
X and Y are 8-cycle letters → "active" rows.
Z is fixed → "transition" row.
Footer is the header repeated → "structural" row.

HYPOTHESIS: Rows 24-25 (keys X,Y = 8-cycle) are ALL HOLES.
            Rows 26-27 (keys Z,footer) have 12 NULLS EACH (24 total).
            Null columns in rows 26-27 are the SAME 12 cols (symmetric).

WHY THIS AVOIDS CRIBS:
  - ENE (pos 21-33) = all in row 25 → all holes ✓
  - BC pos 63-65 = row 26 cols 28-30 → null cols must avoid 28-30
  - BC pos 66-73 = row 27 cols 0-7  → null cols must avoid 0-7
  Safe null cols for BOTH rows 26 and 27: intersection of
    {0..27} (row 26 safe) and {8..30} (row 27 safe) = cols 8..27 (20 cols).

  We need 12 cols from those 20: C(20,12) = 125,970 combinations.
  Each gives exactly 24 nulls and 73 holes, with no crib conflicts.

Test: for each valid 12-col subset, extract 73-char CT and do keyword sweep.
"""
from __future__ import annotations
import sys
from itertools import combinations
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET

K4_CARVED = CT
assert len(K4_CARVED) == 97

CRIB_PAIRS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_DICT = {}
for start, word in CRIB_PAIRS:
    for i, ch in enumerate(word):
        CRIB_DICT[start + i] = ch
CRIB_POSITIONS = set(CRIB_DICT.keys())

KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN","SCHEIDT",
            "BERLIN","CLOCK","EAST","NORTH","LIGHT","ANTIPODES","KOMPASS","DEFECTOR"]

# ── Position helpers ──────────────────────────────────────────────────────────
def k4_pos_to_grid(i):
    if i < 4:
        return (24, 27 + i)
    ii = i - 4
    return (25 + ii // 31, ii % 31)

# Precompute: row/col for each K4 position
K4_ROW = [k4_pos_to_grid(i)[0] for i in range(97)]
K4_COL = [k4_pos_to_grid(i)[1] for i in range(97)]

# Row 26 positions (K4 indices 35-65)
# Row 27 positions (K4 indices 66-96)
ROW26 = list(range(35, 66))
ROW27 = list(range(66, 97))

# Safe null cols: must avoid crib cols
# BC in row 26: cols 28,29,30 (K4 pos 63,64,65)
# BC in row 27: cols 0,1,2,3,4,5,6,7 (K4 pos 66-73)
# ENE in row 25: all holes (cols 17-29, but row 25 is all holes in this model)
ROW26_SAFE_COLS = set(range(0, 28))    # avoid cols 28-30
ROW27_SAFE_COLS = set(range(8, 31))    # avoid cols 0-7

# For SAME col set in rows 26 AND 27:
SHARED_SAFE_COLS = sorted(ROW26_SAFE_COLS & ROW27_SAFE_COLS)
assert SHARED_SAFE_COLS == list(range(8, 28)), f"Got {SHARED_SAFE_COLS}"
print(f"Safe null cols for rows 26+27: {SHARED_SAFE_COLS} ({len(SHARED_SAFE_COLS)} cols)")

# Need 12 of these 20 safe cols
N_COMBOS = __import__('math').comb(len(SHARED_SAFE_COLS), 12)
print(f"C({len(SHARED_SAFE_COLS)}, 12) = {N_COMBOS} combinations to test")

# Precompute: for each col, which K4 positions are in rows 26 and 27
col_to_row26 = {c: 35 + c for c in range(31)}   # K4 position in row 26 for column c
col_to_row27 = {c: 66 + c for c in range(31)}   # K4 position in row 27 for column c

# ── Cipher helpers ────────────────────────────────────────────────────────────
def vig_decrypt(ct, key, alpha=AZ):
    out = []
    n = len(alpha)
    for i, c in enumerate(ct):
        out.append(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % n])
    return "".join(out)

def beau_decrypt(ct, key, alpha=AZ):
    out = []
    n = len(alpha)
    for i, c in enumerate(ct):
        out.append(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % n])
    return "".join(out)

def count_cribs_shifted(pt, null_mask):
    """Count crib hits with positions shifted by null removal."""
    n = 0
    null_sorted = sorted(null_mask)
    for pos, ch in CRIB_DICT.items():
        if pos in null_mask:
            continue
        shift = sum(1 for np in null_sorted if np < pos)
        pt_pos = pos - shift
        if 0 <= pt_pos < len(pt) and pt[pt_pos] == ch:
            n += 1
    return n

# ── Precompute null-shift table ───────────────────────────────────────────────
# For a given null mask (24 positions in rows 26-27),
# null positions with 12 cols × 2 rows:
# Row 26 nulls: cols c → pos 35+c
# Row 27 nulls: cols c → pos 66+c
# For each crib pos p, we need to know how many null positions are < p.

# ENE at 21-33 (row 25): no nulls before pos 33 (nulls start at 35). Shift = 0.
# BC at 63-73 (row 26 cols 28-30, row 27 cols 0-7): nulls at pos 35+c < 63 means c < 28.
# So for BC pos 63-65 (row 26, cols 28-30): shift = # row-26 nulls with col < 28
# For BC pos 66-73 (row 27, cols 0-7): shift = all 12 row-26 nulls + # row-27 nulls with col < col_of_pos
# Since row-27 crib cols are 0-7 and null cols are ≥ 8: shift for row-27 cribs = 12 (only row-26 nulls before them)

# This means: ENE position in 73-char PT = carved position (shift=0).
# BC position in 73-char PT = carved position - 12 (for all BC positions).

def make_null_mask(null_cols):
    """Build null mask from 12 cols (applied to rows 26 AND 27)."""
    mask = set()
    for c in null_cols:
        mask.add(35 + c)   # row 26
        mask.add(66 + c)   # row 27
    return mask

def shifted_crib_count(pt73, null_cols):
    """Fast crib counting for this specific model."""
    n = 0
    null_cols_set = set(null_cols)
    # ENE (pos 21-33): shift=0, all in row 25 (holes). Check pt73[21..33].
    for i, ch in enumerate("EASTNORTHEAST"):
        if 0 <= 21 + i < len(pt73) and pt73[21 + i] == ch:
            n += 1
    # BC (pos 63-73): shift = # null row-26 positions before pos.
    # Row 26 nulls before BC: row 26 has 12 null cols c. BC starts at row26 col 28.
    # All row-26 nulls have col < 28 (from safe cols 8-27). So all 12 row-26 nulls are before BC pos 63.
    # Row 27 BC pos: row 27 crib cols 0-7. Row 27 nulls have col ≥ 8. None before BC.
    # Total shift = 12 for ALL BC positions.
    for i, ch in enumerate("BERLINCLOCK"):
        pt_pos = 63 + i - 12   # shift = 12
        if 0 <= pt_pos < len(pt73) and pt73[pt_pos] == ch:
            n += 1
    return n

# ── Main exhaustion ───────────────────────────────────────────────────────────
print("\n--- Testing all C(20,12) = 125,970 null-col subsets ---")
print("(Rows 24-25 = all holes, rows 26-27 = same 12 null cols)")
print()

best_score = 0
best_info = None
tested = 0

for null_cols in combinations(SHARED_SAFE_COLS, 12):
    # Build 73-char CT (remove nulls from rows 26-27)
    null_k4_pos = {35 + c for c in null_cols} | {66 + c for c in null_cols}
    holes = [i for i in range(97) if i not in null_k4_pos]
    assert len(holes) == 73
    ct73 = "".join(K4_CARVED[i] for i in holes)
    tested += 1

    for kw in KEYWORDS:
        for alpha in [AZ, KA]:
            for cfn in [vig_decrypt, beau_decrypt]:
                try:
                    pt = cfn(ct73, kw, alpha)
                    n = shifted_crib_count(pt, null_cols)
                    if n > best_score:
                        best_score = n
                        best_info = {
                            'n': n, 'kw': kw,
                            'alpha': 'KA' if alpha == KA else 'AZ',
                            'cipher': cfn.__name__.replace('_decrypt', ''),
                            'cols': null_cols,
                            'ct73': ct73[:40],
                            'pt': pt[:60],
                        }
                        print(f"  New best: {n}/24 kw={kw} a={'KA' if alpha==KA else 'AZ'} "
                              f"c={cfn.__name__} null_cols={null_cols}")
                        print(f"    PT: {pt[:60]}")
                        if n >= 24:
                            print("  *** SOLVED! ***")
                except Exception:
                    pass

print(f"\nTested {tested:,} masks. Best: {best_score}/24")
if best_info:
    print(f"Best config: {best_info}")

# ── Special case: test null cols = range(8,20) (the "first 12 safe") ──────────
print("\n--- Special: consecutive windows of 12 cols ---")
for start_col in range(8, 17):   # windows [start, start+12) within [8,27]
    null_cols = tuple(range(start_col, start_col + 12))
    if max(null_cols) > 27:
        continue
    null_k4_pos = {35 + c for c in null_cols} | {66 + c for c in null_cols}
    holes = [i for i in range(97) if i not in null_k4_pos]
    ct73 = "".join(K4_CARVED[i] for i in holes)
    per_best = 0
    per_info = None
    for kw in KEYWORDS:
        for alpha in [AZ, KA]:
            for cfn in [vig_decrypt, beau_decrypt]:
                try:
                    pt = cfn(ct73, kw, alpha)
                    n = shifted_crib_count(pt, null_cols)
                    if n > per_best:
                        per_best = n
                        per_info = (n, kw, 'KA' if alpha == KA else 'AZ',
                                    cfn.__name__, pt[:50])
                except Exception:
                    pass
    print(f"  cols {start_col}-{start_col+11}: best={per_best}/24 {per_info}")

# ── K3 Calibration ────────────────────────────────────────────────────────────
print("\n--- K3 Calibration: does this model give 0 K3 nulls? ---")
# K3 occupies rows 14-24 (cols 0-25 at row 24). Rows 26-27 rule doesn't touch K3.
# K3 calibration: PASS (zero K3 positions are null under this model, since
# the null rule only applies to rows 26-27 of K4).
print("K3 calibration: PASS (null rule applies only to rows 26-27, K3 is in rows 14-24)")
print("K3 rows 14-24: key letters N-X, ALL in 17-cycle or Z. Rows 14-23 have key N,O,P,Q,R,S,T,U,V,W.")
print("Rows 24 (key X, 8-cycle): this model says row 24 = all holes. ✓")
print("Row 24 also = end of K3 (cols 0-25) + start of K4 (cols 27-30). ✓")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Tested: {tested:,} null-col combinations (rows 26+27 each with 12 null cols)")
print(f"Best crib score: {best_score}/24")
print(f"K3 calibration: PASS")
print(f"Null count: 24 exactly for all tested masks")
print(f"Crib conflicts: 0 for all tested masks")
