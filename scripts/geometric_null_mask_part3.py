#!/usr/bin/env python3
"""
Geometric Null-Mask Part 3 — Crib Consistency Testing
=====================================================
For each column-based mask, test whether the 73-char extract has
crib-consistency for the SHIFTED crib positions under various ciphers.

This is critical: after removing 24 nulls, the crib positions SHIFT.
ENE moves from 21-33 to 13-25. BC moves from 63-73 to 47-57 (varies by mask).
The cipher key at the NEW positions must be consistent with a periodic or
structured key.
"""

import sys, os, math
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH_IDX, ALPH, MOD,
    KRYPTOS_ALPHABET
)

GRID_COLS = 31
K4_START_POS = 24 * 31 + 27

def k4_grid_positions():
    positions = []
    grid_pos = K4_START_POS
    for i in range(CT_LEN):
        positions.append((grid_pos // GRID_COLS, grid_pos % GRID_COLS))
        grid_pos += 1
    return positions

K4_GRID = k4_grid_positions()
AVAILABLE_COLS = [8, 9, 10, 11, 12, 13, 14, 15, 16]

def extract_and_map(null_positions):
    """Extract 73 chars and map original positions to new positions."""
    null_set = set(null_positions)
    text_73 = []
    pos_map = {}  # old_pos -> new_pos
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            text_73.append(CT[i])
            pos_map[i] = new_idx
            new_idx += 1
    return ''.join(text_73), pos_map

def derive_keystream(ct_text, pt_positions, variant="vig", alph=ALPH):
    """Derive keystream values at given positions.
    pt_positions: dict of {new_pos: plaintext_char}
    Returns dict of {new_pos: key_value}
    """
    idx = {c: i for i, c in enumerate(alph)}
    keys = {}
    for pos, pt_char in pt_positions.items():
        ci = idx[ct_text[pos]]
        pi = idx[pt_char]
        if variant == "vig":
            keys[pos] = (ci - pi) % 26
        elif variant == "beau":
            keys[pos] = (ci + pi) % 26
        elif variant == "vbeau":
            keys[pos] = (pi - ci) % 26
    return keys

def check_periodic_consistency(keystream, max_period=26):
    """Check if keystream values are consistent with a periodic key.
    Returns list of (period, conflicts) for each period.
    """
    positions = sorted(keystream.keys())
    results = []
    for p in range(1, max_period + 1):
        # Group by position mod period
        groups = {}
        for pos in positions:
            r = pos % p
            groups.setdefault(r, []).append((pos, keystream[pos]))

        conflicts = 0
        for r, vals in groups.items():
            key_vals = set(v for _, v in vals)
            if len(key_vals) > 1:
                conflicts += 1

        consistent_residues = sum(1 for vals in groups.values() if len(set(v for _, v in vals)) == 1)
        total_residues = len(groups)
        results.append((p, conflicts, consistent_residues, total_residues))

    return results


def check_bean_on_73(keystream_73, null_positions):
    """Check Bean constraints mapped to 73-char positions."""
    null_set = set(null_positions)
    pos_map = {}
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            pos_map[i] = new_idx
            new_idx += 1

    # Bean equality: k[27] == k[65] in original → mapped positions
    if 27 in pos_map and 65 in pos_map:
        p27 = pos_map[27]
        p65 = pos_map[65]
        if p27 in keystream_73 and p65 in keystream_73:
            eq_pass = keystream_73[p27] == keystream_73[p65]
        else:
            eq_pass = None
    else:
        eq_pass = None

    return eq_pass

# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("CRIB CONSISTENCY ANALYSIS FOR COLUMN-BASED NULL MASKS")
print("=" * 80)

for kept_col in AVAILABLE_COLS:
    null_cols = set(AVAILABLE_COLS) - {kept_col}
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]

    text_73, pos_map = extract_and_map(nulls)

    # Map crib positions to 73-char positions
    new_cribs = {}
    for orig_pos, pt_char in CRIB_DICT.items():
        if orig_pos in pos_map:
            new_cribs[pos_map[orig_pos]] = pt_char

    print(f"\n{'='*60}")
    print(f"KEPT COLUMN: {kept_col} | Chars at this col: ", end="")
    for r in [25, 26, 27]:
        idx = (r - 25) * 31 + kept_col + 4  # offset for row 24's 4 chars
        if 0 <= idx < CT_LEN:
            print(f"{CT[idx]}", end="")
    print()
    print(f"73-char: {text_73}")

    # New crib position ranges
    ene_new = [pos_map[p] for p in range(21, 34)]
    bc_new = [pos_map[p] for p in range(63, 74)]
    print(f"ENE crib at new positions: {ene_new[0]}-{ene_new[-1]}")
    print(f"BC crib at new positions: {bc_new[0]}-{bc_new[-1]}")

    for variant in ["vig", "beau", "vbeau"]:
        for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            keystream = derive_keystream(text_73, new_cribs, variant, alph)

            # Check Bean equality
            bean_eq = check_bean_on_73(keystream, nulls)

            # Check periodic consistency
            pc_results = check_periodic_consistency(keystream, max_period=20)

            # Find best periods
            best = sorted(pc_results, key=lambda x: x[1])[:3]

            variant_name = {"vig": "Vigenere", "beau": "Beaufort", "vbeau": "VarBeau"}[variant]
            key_values = [keystream[p] for p in sorted(keystream.keys())]

            print(f"\n  {variant_name}/{alph_name}:")
            print(f"    Key at ENE: {[keystream[p] for p in ene_new]}")
            print(f"    Key at BC:  {[keystream[p] for p in bc_new]}")
            print(f"    Bean k[27]==k[65]: {bean_eq}")

            # Show top-3 most consistent periods
            for p, conflicts, consistent, total in best[:3]:
                print(f"    Period {p:2d}: {conflicts} conflicts, {consistent}/{total} residues consistent")

            # Check if any period has 0 conflicts
            zero_conflict = [(p, c, con, tot) for p, c, con, tot in pc_results if c == 0]
            if zero_conflict:
                print(f"    *** ZERO-CONFLICT PERIODS: {[p for p, _, _, _ in zero_conflict]} ***")
                for p, _, _, _ in zero_conflict:
                    # Derive the full key for this period
                    groups = {}
                    for pos in sorted(keystream.keys()):
                        r = pos % p
                        groups.setdefault(r, set()).add(keystream[pos])
                    key_word = ''.join(alph[list(groups[r])[0]] for r in range(p) if r in groups)
                    print(f"      Period {p} key: {key_word}")

                    # Decrypt with this key
                    key_full = ''.join(alph[list(groups[r % p])[0]] if r % p in groups else '?' for r in range(p))
                    if '?' not in key_full:
                        # Full decrypt
                        if variant == "vig":
                            pt = ''.join(alph[(ALPH_IDX[c] - ALPH_IDX[key_full[i % p]]) % 26]
                                        for i, c in enumerate(text_73))
                        elif variant == "beau":
                            pt = ''.join(alph[(ALPH_IDX[key_full[i % p]] - ALPH_IDX[c]) % 26]
                                        for i, c in enumerate(text_73))
                        else:
                            pt = ''.join(alph[(ALPH_IDX[c] + ALPH_IDX[key_full[i % p]]) % 26]
                                        for i, c in enumerate(text_73))
                        print(f"      Decrypted: {pt}")

                        # Check for English-like patterns
                        from collections import Counter
                        freq = Counter(pt)
                        top5 = freq.most_common(5)
                        print(f"      Top 5 freq: {top5}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("STAGGERED DIAGONAL MASKS — CRIB CONSISTENCY")
print("=" * 80)

# The most interesting staggered masks from Part 2
staggered_configs = [
    # (base, shifts, description)
    (8, (0, 0, 1), "base=8 shift 0,0,1 — 24° step"),
    (7, (0, 1, 2), "base=7 shift 0,1,2 — full 24° stagger"),
    (8, (0, 1, 2), "base=8 shift 0,1,2 — full 24° stagger"),
    (6, (0, 1, 2), "base=6 shift 0,1,2 — full 24° stagger"),
]

for base, shifts, desc in staggered_configs:
    nulls = []
    null_cols_per_row = {}
    for row, shift in zip([25, 26, 27], shifts):
        cols = set((base + shift + j) % GRID_COLS for j in range(8))
        null_cols_per_row[row] = cols
        for i, (r, c) in enumerate(K4_GRID):
            if r == row and c in cols:
                nulls.append(i)

    if len(nulls) != 24:
        continue
    if set(nulls) & CRIB_POSITIONS:
        continue

    text_73, pos_map = extract_and_map(nulls)
    new_cribs = {}
    for orig_pos, pt_char in CRIB_DICT.items():
        if orig_pos in pos_map:
            new_cribs[pos_map[orig_pos]] = pt_char

    ene_new = [pos_map[p] for p in range(21, 34)]
    bc_new = [pos_map[p] for p in range(63, 74)]

    print(f"\n--- {desc} ---")
    print(f"  Row 25: null cols {sorted(null_cols_per_row[25])}")
    print(f"  Row 26: null cols {sorted(null_cols_per_row[26])}")
    print(f"  Row 27: null cols {sorted(null_cols_per_row[27])}")
    print(f"  73-char: {text_73}")
    print(f"  ENE: {ene_new[0]}-{ene_new[-1]}, BC: {bc_new[0]}-{bc_new[-1]}")

    for variant in ["vig", "beau"]:
        for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            keystream = derive_keystream(text_73, new_cribs, variant, alph)
            pc_results = check_periodic_consistency(keystream, max_period=20)
            best3 = sorted(pc_results, key=lambda x: x[1])[:3]
            zero_conflict = [(p, c, con, tot) for p, c, con, tot in pc_results if c == 0]

            variant_name = {"vig": "Vigenere", "beau": "Beaufort"}[variant]
            print(f"  {variant_name}/{alph_name}: best periods = ", end="")
            for p, conflicts, _, _ in best3:
                print(f"p={p}({conflicts}c) ", end="")
            if zero_conflict:
                print(f" *** ZERO-CONFLICT: {[p for p, _, _, _ in zero_conflict]} ***", end="")
            print()

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("KEY INSIGHT: THE 3-ZONE GRID STRUCTURE")
print("=" * 80)

print("""
CRITICAL OBSERVATION: K4's crib positions create a natural 3-zone structure
in the 31-column grid that is NOT arbitrary:

  Zone A (cols 0-7):   8 cols — contains BC crib (rows 26-27)
  Zone B (cols 8-16):  9 cols — NO cribs in ANY row
  Zone C (cols 17-30): 14 cols — contains ENE crib (row 25) + BC crib start (row 26)

Zone B's width of 9 columns has a REMARKABLE geometric property:
  4 rows (K4 height) / 9 columns (null band) = tan(23.96°) ≈ tan(24°)

This means: if you draw a line at 24° from one corner of K4's bounding box
to the opposite corner, it sweeps exactly through the null band width.

The 3-zone structure means:
  Zone A + Zone C = 22 columns → 22 × 3 full rows + 4 (row 24) = 70 chars
  Zone B keeps 1 of 9 columns → adds 3 more chars
  Total: 73 chars ✓

The crib-free gap in the middle of K4 is itself a GEOMETRIC feature of the
two cribs' positions — they leave a 9-column "shadow" that corresponds to
the 24° angle parameter.

NEXT STEPS:
1. Which single column (8-16) the grille keeps may be encoded in another
   geometric parameter (e.g., compass bearing, lodestone offset)
2. The staggered shift (24° diagonal sliding across rows) creates
   additional mask variants — some may have better crib consistency
3. After null removal, the cipher layer may be NON-periodic
   (running key, autokey, or custom tableau)
""")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("ENUMERATION: ALL CRIB-CONSISTENT MASKS IN THE NULL BAND")
print("=" * 80)

print("""
Rather than 8 identical columns, test ALL ways to choose exactly 8 positions
per row from columns 8-16 (allowing different columns per row):
C(9,8)^3 = 9^3 = 729 combinations.
""")

valid_mask_count = 0
best_consistency = []

for r25_combo in combinations(AVAILABLE_COLS, 8):
    for r26_combo in combinations(AVAILABLE_COLS, 8):
        for r27_combo in combinations(AVAILABLE_COLS, 8):
            nulls = []
            for i, (r, c) in enumerate(K4_GRID):
                if r == 25 and c in set(r25_combo):
                    nulls.append(i)
                elif r == 26 and c in set(r26_combo):
                    nulls.append(i)
                elif r == 27 and c in set(r27_combo):
                    nulls.append(i)

            if len(nulls) != 24:
                continue
            if set(nulls) & CRIB_POSITIONS:
                continue

            valid_mask_count += 1

            text_73, pos_map = extract_and_map(nulls)
            new_cribs = {}
            for orig_pos, pt_char in CRIB_DICT.items():
                if orig_pos in pos_map:
                    new_cribs[pos_map[orig_pos]] = pt_char

            # Quick consistency check: Beaufort/AZ
            ks = derive_keystream(text_73, new_cribs, "beau", ALPH)
            pc = check_periodic_consistency(ks, max_period=15)
            best_period = min(pc, key=lambda x: x[1])

            if best_period[1] == 0:
                kept_r25 = set(AVAILABLE_COLS) - set(r25_combo)
                kept_r26 = set(AVAILABLE_COLS) - set(r26_combo)
                kept_r27 = set(AVAILABLE_COLS) - set(r27_combo)
                best_consistency.append({
                    'kept': (kept_r25, kept_r26, kept_r27),
                    'period': best_period[0],
                    'text_73': text_73,
                    'nulls': nulls,
                })

            # Also check Vigenere/AZ
            ks_v = derive_keystream(text_73, new_cribs, "vig", ALPH)
            pc_v = check_periodic_consistency(ks_v, max_period=15)
            best_v = min(pc_v, key=lambda x: x[1])
            if best_v[1] == 0:
                kept_r25 = set(AVAILABLE_COLS) - set(r25_combo)
                kept_r26 = set(AVAILABLE_COLS) - set(r26_combo)
                kept_r27 = set(AVAILABLE_COLS) - set(r27_combo)
                best_consistency.append({
                    'kept': (kept_r25, kept_r26, kept_r27),
                    'period': best_v[0],
                    'text_73': text_73,
                    'nulls': nulls,
                    'variant': 'vig',
                })

            # Beaufort/KA
            ks_bk = derive_keystream(text_73, new_cribs, "beau", KRYPTOS_ALPHABET)
            pc_bk = check_periodic_consistency(ks_bk, max_period=15)
            best_bk = min(pc_bk, key=lambda x: x[1])
            if best_bk[1] == 0:
                kept_r25 = set(AVAILABLE_COLS) - set(r25_combo)
                kept_r26 = set(AVAILABLE_COLS) - set(r26_combo)
                kept_r27 = set(AVAILABLE_COLS) - set(r27_combo)
                best_consistency.append({
                    'kept': (kept_r25, kept_r26, kept_r27),
                    'period': best_bk[0],
                    'text_73': text_73,
                    'nulls': nulls,
                    'variant': 'beau/KA',
                })

print(f"\nTotal valid masks (729 row-combinations): {valid_mask_count}")
print(f"Masks with zero-conflict periodic consistency: {len(best_consistency)}")

if best_consistency:
    print("\nZero-conflict results:")
    for r in best_consistency[:20]:
        print(f"  Kept cols: R25={r['kept'][0]}, R26={r['kept'][1]}, R27={r['kept'][2]}")
        print(f"  Period: {r['period']}, Variant: {r.get('variant', 'beau/AZ')}")
        print(f"  73-char: {r['text_73']}")

        # Decrypt
        text_73 = r['text_73']
        nulls = r['nulls']
        new_cribs = {}
        _, pos_map = extract_and_map(nulls)
        for orig_pos, pt_char in CRIB_DICT.items():
            if orig_pos in pos_map:
                new_cribs[pos_map[orig_pos]] = pt_char

        variant = r.get('variant', 'beau/AZ')
        if '/' in variant:
            v, a = variant.split('/')
        else:
            v, a = variant, 'AZ'
        alph = ALPH if a == 'AZ' else KRYPTOS_ALPHABET

        ks = derive_keystream(text_73, new_cribs, v if v != 'beau' else 'beau', alph)
        p = r['period']

        # Get key values by residue
        groups = {}
        for pos in sorted(ks.keys()):
            residue = pos % p
            groups.setdefault(residue, set()).add(ks[pos])

        # Check if fully determined
        key_word = []
        for residue in range(p):
            if residue in groups:
                vals = groups[residue]
                if len(vals) == 1:
                    key_word.append(alph[list(vals)[0]])
                else:
                    key_word.append('?')
            else:
                key_word.append('?')
        print(f"  Key: {''.join(key_word)}")
        print()

print("\nDone.")
