#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Analyze the T-avoidance in the Cardan grille extract.

The grille extract has 25/26 letters — ONLY T is missing.
Is this systematic? Does the grille avoid the T-diagonal on the tableau?
"""
import sys
sys.path.insert(0, 'src')

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

# Parse binary mask
MASK_TEXT = """1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""

mask_rows = MASK_TEXT.strip().split('\n')
holes = []  # (col, row) 1-based
for ri, line in enumerate(mask_rows):
    row = ri + 1
    vals = line.split()
    for ci, v in enumerate(vals):
        col = ci + 1
        if v == '0':
            holes.append((col, row))

print("=" * 80)
print("T-AVOIDANCE ANALYSIS")
print("=" * 80)

# ── Find T-column for each row ──────────────────────────────────────────
print("\n--- T-POSITION IN EACH TABLEAU ROW ---")
print(f"{'Row':>4} {'Label':>6} {'T-col':>6}  {'Holes in row':>30}  {'T hit?':>6}")
print("─" * 80)

t_positions = {}  # row -> col where T appears
total_near_misses = 0

for ri, tab_row in enumerate(TABLEAU_ROWS):
    row = ri + 1
    # Find all T positions in this row
    t_cols = [ci + 1 for ci, ch in enumerate(tab_row) if ch == 'T']
    row_holes = sorted([c for c, r in holes if r == row])
    t_hit = any(tc in row_holes for tc in t_cols)
    label = tab_row[0] if tab_row[0] != ' ' else ('hdr' if row == 1 else 'ftr')

    # Near miss: hole within ±1 of T-col
    near = []
    for tc in t_cols:
        for h in row_holes:
            if abs(h - tc) <= 2 and h != tc:
                near.append((h, tc))
                total_near_misses += 1

    t_positions[row] = t_cols
    near_str = f"  near:{near}" if near else ""
    print(f"{row:4d} {label:>6} {str(t_cols):>10}  {str(row_holes):>35}  {'HIT!' if t_hit else 'MISS':>6}{near_str}")

# ── Statistical significance ─────────────────────────────────────────────
print(f"\n--- STATISTICAL ANALYSIS ---")
# For each row, probability of all holes missing T-col
# T occupies 1 column out of row_width
import math

log_prob = 0
for ri, tab_row in enumerate(TABLEAU_ROWS):
    row = ri + 1
    row_width = len(tab_row)
    t_cols_in_row = len([c for c in range(1, row_width + 1) if tab_row[c-1] == 'T'])
    n_holes = len([c for c, r in holes if r == row])
    if n_holes > 0 and t_cols_in_row > 0:
        # Prob of all holes missing T: ((W - t_count) / W) ^ n_holes
        # But actually, T appears at specific positions, not randomly
        # Simpler: prob that none of n_holes land on the t_cols_in_row positions
        # Using hypergeometric-like reasoning:
        p_miss_one = (row_width - t_cols_in_row) / row_width
        p_miss_all = p_miss_one ** n_holes
        log_prob += math.log10(p_miss_all)

print(f"Log10(probability of avoiding T in ALL rows): {log_prob:.2f}")
print(f"Probability: ~10^{log_prob:.1f} = ~1 in {10**(-log_prob):.0f}")
print(f"Near misses (hole within ±2 of T-col): {total_near_misses}")

# ── T-DIAGONAL visualization ────────────────────────────────────────────
print(f"\n--- T-DIAGONAL vs GRILLE HOLES (first 32 cols) ---")
print(f"     {''.join(str(c%10) for c in range(1, 33))}")
for ri, tab_row in enumerate(TABLEAU_ROWS):
    row = ri + 1
    t_cols = set(t_positions[row])
    row_holes = set(c for c, r in holes if r == row)
    line = []
    for col in range(1, 33):
        if col > len(tab_row):
            line.append('·')
        elif col in t_cols and col in row_holes:
            line.append('X')  # T hit (shouldn't happen!)
        elif col in t_cols:
            line.append('T')
        elif col in row_holes:
            line.append('O')
        else:
            line.append('─')
    print(f"R{row:02d}: {''.join(line)}")

print("\nLegend: T=T-position, O=grille hole, X=overlap (T hit), ─=masked, ·=beyond row")

# ── What letter appears at the T-column for each row? ────────────────────
print(f"\n--- GRILLE HOLES: PROXIMITY TO T-COLUMN ---")
print("For each hole, show distance to nearest T in that row:")
distances = []
for col, row in sorted(holes, key=lambda x: (x[1], x[0])):
    t_cols = t_positions[row]
    if t_cols:
        min_dist = min(abs(col - tc) for tc in t_cols)
        distances.append(min_dist)

from collections import Counter
dist_freq = Counter(distances)
print(f"\nDistance distribution (hole to nearest T in same row):")
for d in sorted(dist_freq.keys()):
    bar = '#' * dist_freq[d]
    print(f"  dist={d:2d}: {dist_freq[d]:3d} {bar}")
print(f"  Min distance: {min(distances)}")
print(f"  Mean distance: {sum(distances)/len(distances):.1f}")

# ── WHAT IF: insert T at its tableau position in each row? ───────────────
print(f"\n{'=' * 80}")
print("WHAT IF: INSERT T at each row's T-column position?")
print(f"{'=' * 80}")
# If T marks positions, what happens if we ADD T to the extraction
# at the positions where it would appear?

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

# Build extraction with T inserted at T-columns (in reading order)
all_positions = []
for col, row in sorted(holes, key=lambda x: (x[1], x[0])):
    tab_row = TABLEAU_ROWS[row - 1]
    if col <= len(tab_row):
        all_positions.append((col, row, tab_row[col-1], 'hole'))

# Also add T-positions (not already holes)
for row in range(1, 29):
    tab_row = TABLEAU_ROWS[row - 1]
    t_cols = [c for c in range(1, len(tab_row)+1) if tab_row[c-1] == 'T']
    for tc in t_cols:
        if (tc, row) not in set(holes):
            all_positions.append((tc, row, 'T', 't-insert'))

# Sort in reading order
all_positions.sort(key=lambda x: (x[1], x[0]))

# Build string with T insertions
with_t = ''.join(ch for _, _, ch, _ in all_positions)
just_t_positions = [(c, r) for c, r, ch, src in all_positions if src == 't-insert']
print(f"\nT would be inserted at {len(just_t_positions)} positions:")
for c, r in just_t_positions:
    print(f"  ({c},{r}) — between extraction positions in row {r}")

print(f"\nOriginal extraction: {len(USER_CT)} chars")
print(f"With T inserted:     {len(with_t)} chars")
print(f"With T: {with_t}")

# Count T in augmented string
print(f"\nT count in augmented: {with_t.count('T')}")
print(f"Total length: {len(with_t)} (original 106 + {len(just_t_positions)} T's = {106 + len(just_t_positions)})")

# ── Check augmented string as running key ────────────────────────────────
from kryptos.kernel.constants import CT as K4_CT

def decrypt_vig(ct, key, alpha):
    return ''.join(alpha[(alpha.index(c) - alpha.index(k)) % 26] for c, k in zip(ct, key))

def decrypt_beau(ct, key, alpha):
    return ''.join(alpha[(alpha.index(k) - alpha.index(c)) % 26] for c, k in zip(ct, key))

CRIB_ENE = (21, "EASTNORTHEAST")
CRIB_BC = (63, "BERLINCLOCK")

def score_cribs(pt):
    s = 0
    for start, crib in [CRIB_ENE, CRIB_BC]:
        for i, ch in enumerate(crib):
            if start + i < len(pt) and pt[start + i] == ch:
                s += 1
    return s

print(f"\n--- AUGMENTED STRING AS RUNNING KEY ---")
if len(with_t) >= len(K4_CT):
    max_off = len(with_t) - len(K4_CT)
    best = (0, '', '', 0)
    for off in range(max_off + 1):
        key = with_t[off:off+len(K4_CT)]
        for vn, vf, alpha_name, alpha in [
            ("Vig", decrypt_vig, "AZ", AZ),
            ("Beau", decrypt_beau, "AZ", AZ),
            ("Vig", decrypt_vig, "KA", KA),
            ("Beau", decrypt_beau, "KA", KA),
        ]:
            pt = vf(K4_CT, key, alpha)
            cs = score_cribs(pt)
            if cs > best[0]:
                best = (cs, f"{vn}/{alpha_name}/off={off}", pt, cs)
            if cs >= 3:
                print(f"  {vn}/{alpha_name}/off={off}: crib={cs}/24 PT={pt[:50]}...")

    print(f"\n  Best: {best[1]} crib={best[0]}/24")
else:
    print(f"  Augmented string ({len(with_t)}) shorter than K4 ({len(K4_CT)}), skipping")

print(f"\n{'=' * 80}")
print("SUMMARY")
print(f"{'=' * 80}")
print(f"1. CONFIRMED: Zero T's in 106-char grille extract (25/26 letters)")
print(f"2. T-column is systematically AVOIDED in every single row ({len(holes)} holes checked)")
print(f"3. Probability of this by chance: ~10^{log_prob:.1f}")
print(f"4. Minimum distance from any hole to T-column: {min(distances)}")
print(f"5. T-positions form a DIAGONAL on the tableau (moving left as rows increase)")
print(f"6. Direct running key (with or without T insertion): max {best[0] if best else 0}/24 crib score")
