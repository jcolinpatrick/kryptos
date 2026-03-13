#!/usr/bin/env python3
"""
grille_8cycle_col_cribs.py   [Approach B, 2026-03-13]

HYPOTHESIS: The Kryptos tableau HEADER defines which columns are grille holes
vs solid cells.  The tableau header is " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
(cols 0-30).  The 8-cycle letters of AZ→KA (C,J,Q,U,V,W,X,Y) appear at
header cols {3,10,17,21,22,23,24,25}.

For K4 rows 25-27 (31 cols each = 93 positions):
  8-cycle header cols × 3 rows = 8 × 3 = 24 null positions (EXACTLY 24!)
  17-cycle + Z cols × 3 rows = 23 × 3 = 69 holes

For K4 row 24 (cols 27-30 = 4 positions): ALL holes (opening row).
  TOTAL HOLES = 73, NULLS = 24  ✓

K3 CALIBRATION: K3 occupies rows 14-24 (cols 0-25 at row 24).
  In K3's region, the same rule applied to rows 14-23 (full rows 0-30)
  would also mark 8-cycle cols as nulls.  This FAILS K3 (K3 has no nulls).
  UNLESS K3 is exempt because the tableau header is different for rows 0-13.

TWO VARIANTS TESTED:
  Variant A: "Shifted cribs" — crib positions 21-33 refer to 73-char PT, not
             the carved text. Under null removal, find the 73-char CT positions
             where EASTNORTHEAST and BERLINCLOCK must appear.
  Variant B: The null positions avoid all 24 crib positions. We permute
             which 8 short cols are nulls to find a set of 8 cols (24 positions)
             that doesn't intersect the 24 cribs. (Very few options exist.)
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

# ── AZ→KA cycles ─────────────────────────────────────────────────────────────
AZ_to_KA_idx = [KA.index(AZ[i]) for i in range(26)]

def get_cycles():
    visited = [False] * 26
    cycles = {}
    cid = 0
    for start in range(26):
        if not visited[start]:
            cur = start
            while not visited[cur]:
                visited[cur] = True
                cycles[AZ[cur]] = cid
                cur = AZ_to_KA_idx[cur]
            cid += 1
    return cycles

LETTER_CYCLE = get_cycles()
# Cycles: 0=17-cycle (A,H,O,F,M,S,G,N,T,E,L,R,B,I,P,D,K)
#         1=8-cycle  (C,J,Q,U,V,W,X,Y)
#         2=fixed    (Z)

# ── Tableau header ────────────────────────────────────────────────────────────
# " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" — col 0=space, cols 1-26=A-Z, cols 27-30=A-D
def header_letter(c):
    """Tableau header letter at column c (0-indexed)."""
    if c == 0:
        return ' '
    return AZ[(c - 1) % 26]

# 8-cycle cols in 0-30:
EIGHT_CYCLE_COLS = [c for c in range(31)
                    if header_letter(c) != ' '
                    and LETTER_CYCLE.get(header_letter(c), -1) == 1]
print(f"8-cycle header cols: {EIGHT_CYCLE_COLS}")
print(f"  Header letters: {[header_letter(c) for c in EIGHT_CYCLE_COLS]}")

# ── K4 position mapping ───────────────────────────────────────────────────────
def k4_pos_to_grid(i):
    if i < 4:
        return (24, 27 + i)
    ii = i - 4
    return (25 + ii // 31, ii % 31)

# Build: col → list of K4 positions in that column (rows 25,26,27 only)
col_to_k4_short = {}
for i in range(4, 97):   # rows 25-27
    r, c = k4_pos_to_grid(i)
    col_to_k4_short.setdefault(c, []).append(i)

# ── Build the canonical null mask (8-cycle header cols, rows 25-27) ──────────
CANONICAL_NULL_MASK = set()
for c in EIGHT_CYCLE_COLS:
    for i in col_to_k4_short.get(c, []):
        CANONICAL_NULL_MASK.add(i)

print(f"\nCanonical null mask: {len(CANONICAL_NULL_MASK)} nulls")
print(f"  Null positions: {sorted(CANONICAL_NULL_MASK)}")
crib_conflicts = CANONICAL_NULL_MASK & CRIB_POSITIONS
print(f"  Crib conflicts: {sorted(crib_conflicts)} ({len(crib_conflicts)} conflicts)")

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

# ── Variant A: Shifted cribs ──────────────────────────────────────────────────
print("\n" + "=" * 60)
print("VARIANT A: Test canonical mask with SHIFTED crib positions")
print("=" * 60)

def count_shifted_cribs(pt73, null_mask):
    """Cribs at ORIGINAL carved positions, shifted by null removal."""
    n = 0
    for carved_pos, ch in CRIB_DICT.items():
        if carved_pos in null_mask:
            continue
        shift = sum(1 for np in null_mask if np < carved_pos)
        pt73_pos = carved_pos - shift
        if 0 <= pt73_pos < len(pt73) and pt73[pt73_pos] == ch:
            n += 1
    return n

holes = sorted(set(range(97)) - CANONICAL_NULL_MASK)
ct73 = "".join(K4_CARVED[i] for i in holes)
print(f"73-char CT: {ct73}")

# Shifted crib positions
print("\nShifted crib analysis:")
for carved_pos, ch in sorted(CRIB_DICT.items()):
    if carved_pos in CANONICAL_NULL_MASK:
        print(f"  Carved[{carved_pos:2d}]={ch}  → NULL (no PT equivalent)")
    else:
        shift = sum(1 for np in CANONICAL_NULL_MASK if np < carved_pos)
        pt73_pos = carved_pos - shift
        print(f"  Carved[{carved_pos:2d}]={ch}  → PT73[{pt73_pos:2d}] "
              f"(shift={shift})")

best_score_A = 0
for kw in KEYWORDS:
    for aname, alpha in [("AZ", AZ), ("KA", KA)]:
        for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            try:
                pt = cfn(ct73, kw, alpha)
                n = count_shifted_cribs(pt, CANONICAL_NULL_MASK)
                if n >= 10:
                    print(f"  {n:2d}/24 cribs [{cname}/{kw}/{aname}]: {pt[:60]}")
                best_score_A = max(best_score_A, n)
            except Exception:
                pass
print(f"Best score (shifted cribs): {best_score_A}/24")

# ── Variant B: Find 8-col subsets that avoid crib positions ─────────────────
print("\n" + "=" * 60)
print("VARIANT B: Search for 8-col subsets avoiding all 24 cribs")
print("=" * 60)

# Short cols 0-30 (all, not just 8-cycle)
# We need 8 cols from rows 25-27 such that none of the 24 positions
# are in CRIB_POSITIONS, and total selected = 24
# Crib positions in rows 25-27: compute
crib_in_rows25_27 = {i for i in CRIB_POSITIONS if i >= 4}
print(f"Crib positions in rows 25-27 (K4 pos 4-96): {sorted(crib_in_rows25_27)}")
crib_cols = set()
for cp in crib_in_rows25_27:
    _, c = k4_pos_to_grid(cp)
    crib_cols.add(c)
print(f"Cols containing crib positions: {sorted(crib_cols)}")
# These cols CANNOT be null cols
non_crib_short_cols = [c for c in range(31) if c not in crib_cols]
print(f"Non-crib cols (candidates for null): {non_crib_short_cols} ({len(non_crib_short_cols)} total)")
print(f"Need to pick 8 from these to get 24 nulls (8×3=24)")

# Also check row 24 (cols 27-30): crib positions in row 24
crib_in_row24 = {i for i in CRIB_POSITIONS if i < 4}
print(f"Crib positions in row 24 (K4 pos 0-3): {sorted(crib_in_row24)}")

# How many cols can we choose from?
n_candidates = len(non_crib_short_cols)
print(f"\nC({n_candidates},8) = {__import__('math').comb(n_candidates, 8)} possible 8-col subsets to test")

if __import__('math').comb(n_candidates, 8) < 2000000:
    best_score_B = 0
    best_B_info = None
    tested = 0
    for cols in combinations(non_crib_short_cols, 8):
        null_mask = set()
        for c in cols:
            for i in col_to_k4_short.get(c, []):
                null_mask.add(i)
        # Verify: 24 nulls, 73 holes, no crib conflicts
        if len(null_mask) != 24:
            continue
        if null_mask & CRIB_POSITIONS:
            continue
        holes_b = sorted(set(range(97)) - null_mask)
        if len(holes_b) != 73:
            continue
        ct73_b = "".join(K4_CARVED[i] for i in holes_b)
        tested += 1
        for kw in KEYWORDS:
            for alpha in [AZ, KA]:
                for cfn in [vig_decrypt, beau_decrypt]:
                    try:
                        pt = cfn(ct73_b, kw, alpha)
                        n = sum(1 for pos, ch in CRIB_DICT.items()
                                if pos not in null_mask
                                and 0 <= pos - sum(1 for np in null_mask if np < pos) < len(pt)
                                and pt[pos - sum(1 for np in null_mask if np < pos)] == ch)
                        if n > best_score_B:
                            best_score_B = n
                            best_B_info = (n, cols, kw, alpha == KA, pt[:60])
                            if n >= 18:
                                print(f"  *** SIGNAL: {n}/24 cols={cols} kw={kw} pt={pt[:60]}")
                    except Exception:
                        pass
    print(f"Tested {tested} valid 8-col subsets avoiding cribs")
    print(f"Best score (B): {best_score_B}/24")
    if best_B_info:
        print(f"  Best: {best_B_info}")
else:
    print("Too many combinations — running partial test (first 10K)")
    tested = best_score_B = 0
    best_B_info = None
    for i, cols in enumerate(combinations(non_crib_short_cols, 8)):
        if i >= 10000:
            break
        null_mask = set()
        for c in cols:
            for j in col_to_k4_short.get(c, []):
                null_mask.add(j)
        if len(null_mask) != 24 or null_mask & CRIB_POSITIONS:
            continue
        holes_b = sorted(set(range(97)) - null_mask)
        ct73_b = "".join(K4_CARVED[j] for j in holes_b)
        tested += 1
        for kw in KEYWORDS[:5]:
            for cfn in [vig_decrypt, beau_decrypt]:
                try:
                    pt = cfn(ct73_b, kw, AZ)
                    n = sum(1 for pos, ch in CRIB_DICT.items()
                            if pos not in null_mask
                            and pt[pos - sum(1 for np in null_mask if np < pos)] == ch)
                    if n > best_score_B:
                        best_score_B = n
                        best_B_info = (n, cols, kw, pt[:60])
                except Exception:
                    pass
    print(f"Tested {tested} subsets (partial). Best: {best_score_B}/24")

# ── K3 Calibration for 8-cycle col rule ──────────────────────────────────────
print("\n" + "=" * 60)
print("K3 CALIBRATION for 8-cycle col rule")
print("=" * 60)

K3_CARVED = ""
for r in range(14, 24):
    K3_CARVED += "".join(CIPHER_ROWS_RAW[r][:31])
K3_CARVED += CIPHER_ROWS_RAW[24][:26]
assert len(K3_CARVED) == 336, f"K3 length {len(K3_CARVED)}"

def k3_pos_to_grid(i):
    if i < 310:
        return (14 + i // 31, i % 31)
    return (24, i - 310)

# K3 would have nulls at 8-cycle cols too (rows 14-23 have 31 cols, row 24 has 26 cols)
k3_null_positions = []
for i in range(336):
    r, c = k3_pos_to_grid(i)
    hl = header_letter(c)
    if hl != ' ' and LETTER_CYCLE.get(hl, -1) == 1:
        k3_null_positions.append(i)

print(f"8-cycle col rule applied to K3: {len(k3_null_positions)} null positions")
print(f"  (K3 calibration expects 0. Got {len(k3_null_positions)} → FAIL)")
print(f"  This means the rule is NOT globally uniform: K3 rows use different logic")
print(f"  OR: the grille covers only K4 rows (24-27) with this rule")

# Summary
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"8-cycle header cols = {sorted(c for c in EIGHT_CYCLE_COLS if c < 27)} (short cols only)")
print(f"These give exactly 24 K4 nulls (rows 25-27, 8 cols × 3 = 24)")
print(f"BUT: {len(crib_conflicts)} of 24 cribs are in the null set")
print(f"   (Rule fails if cribs are at carved text positions)")
print(f"   (Rule may work if cribs apply to shifted 73-char PT)")
print(f"Best score variant A (shifted): {best_score_A}/24")
print(f"Best score variant B (avoid cribs): {best_score_B}/24")
print(f"K3 calibration: FAIL ({len(k3_null_positions)} K3 positions marked null by rule)")
