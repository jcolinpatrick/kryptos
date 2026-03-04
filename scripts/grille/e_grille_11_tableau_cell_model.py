#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-GRILLE-11: Analytical — Tableau Cell Correspondence Model.

NOVEL ANALYTICAL CHECK: Tests whether the physical Cardan grille holes
mark the EXACT tableau cells used during K4's encryption/decryption.

THEORY: In Vigenère encryption, each position i uses tableau cell
(row=key_letter_row, col=PT_letter_col). If the Cardan grille was designed
to show WHICH cells of the tableau were used for K4, then the 97 cells
(row=k[i], col=PT[i]) for i=0..96 should all be holes in the grille.

PRIOR RESULT (from agent_analysis.json 2026-03-02):
  24 crib positions: only 1/24 have their "used" tableau cell in VISIBLE_CELLS.
  Expected under random: ~2.8/24. Actual 1/24 is BELOW chance.
  CONCLUSION: "Grille marks used tableau cells" model ELIMINATED.

THIS SCRIPT:
1. Formally verifies the 1/24 hit rate for Vigenère
2. Checks Beaufort and Var-Beaufort variants
3. NOVEL: Tests the INVERSE — which grille cells correspond to WHICH K4 positions?
   For each grille hole at (col, row), identify which (key, CT) pair would place
   that hole in the encryption path. This tells us what K4 positions the grille
   "wants" to illuminate.
4. Generates the "grille-compatible keystream": for each K4 position, what key
   values are REACHABLE from any single grille hole? (The set of key values
   that would cause a given CT[i] to be encoded through a grille hole.)
5. Checks if the 24 known key values are all in their respective "reachable" sets.
   If ANY crib key value is NOT reachable from any grille hole, the grille-based
   key model (of any kind) is eliminated for that cipher variant.

KEY FORMULA:
For Vigenère: tableau[key_row][pt_col] = CT_letter
  where key_row = AZ.index(key_letter) + 1 (body row, 0-indexed)
        pt_col = AZ.index(PT_letter)  (body col, 0-indexed)
If the hole is at grid position (col, row) [1-based in 28×33 grid]:
  KA_row_index = row - 2  (0-25 for body rows, skip header at row=1)
  key_letter = AZ[KA_row_index]  (since tableau body rows A=2, B=3, ..., Z=27)
  body_col = col - 2  (0-25, skip label at col=1)
  CT_produced = KA[(body_col + KA_row_index) mod 26]

For K4 position i to pass through grille hole (col, row):
  CT[i] must equal KA[(col-2 + row-2) mod 26]

So the set of K4 positions that could be associated with hole (col, row) is:
  {i : CT[i] == KA[(col-2 + row-2) mod 26]}

Usage: PYTHONPATH=src python3 -u scripts/e_grille_11_tableau_cell_model.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-11"

CT_K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(CT_K4) == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

CRIB_PT: Dict[int, str] = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'
}
CRIB_KEYS_VIG: Dict[int, int] = {
    21: 1, 22: 11, 23: 25, 24: 2, 25: 3, 26: 2, 27: 24, 28: 24,
    29: 6, 30: 2, 31: 10, 32: 0, 33: 25,
    63: 12, 64: 20, 65: 24, 66: 10, 67: 11, 68: 6, 69: 10, 70: 14, 71: 17, 72: 13, 73: 0,
}
CRIB_KEYS_BEAU: Dict[int, int] = {
    21: 9, 22: 11, 23: 9, 24: 14, 25: 3, 26: 4, 27: 6, 28: 10, 29: 20,
    30: 10, 31: 10, 32: 10, 33: 11,
    63: 14, 64: 2, 65: 6, 66: 6, 67: 1, 68: 6, 69: 14, 70: 10, 71: 19,
    72: 17, 73: 20,
}

VISIBLE_CELLS = [
    (9,1), (11,1), (13,1), (23,1), (33,1),
    (1,2), (11,2), (17,2), (21,2), (26,2), (27,2), (32,2), (33,2),
    (15,3), (32,3), (33,3),
    (21,4), (28,4), (31,4), (32,4), (33,4),
    (8,5), (17,5), (22,5), (31,5), (32,5), (33,5),
    (9,6), (31,6), (32,6), (33,6),
    (1,7), (32,7), (33,7),
    (24,8), (30,8), (32,8), (33,8),
    (20,9), (28,9), (33,9),
    (29,10), (32,10), (33,10),
    (9,11), (31,11), (32,11), (33,11),
    (6,12), (7,12), (30,12), (32,12), (33,12),
    (15,13), (18,13), (19,13), (32,13), (33,13),
    (12,14), (28,14), (33,14),
    (4,15), (5,15), (7,15), (13,15), (26,15), (30,15), (32,15), (33,15),
    (5,16), (7,16), (25,16), (31,16), (32,16), (33,16),
    (3,17), (6,17), (11,17), (12,17), (13,17), (28,17), (30,17), (32,17), (33,17),
    (12,18), (13,18), (22,18), (27,18), (31,18), (32,18), (33,18),
    (14,19), (18,19), (21,19), (29,19), (30,19), (31,19), (32,19), (33,19),
    (17,20), (20,20), (29,20), (30,20), (32,20), (33,20),
    (9,21), (10,21), (17,21), (19,21), (21,21), (25,21), (28,21), (31,21), (32,21), (33,21),
    (16,22), (21,22), (23,22), (25,22), (27,22), (32,22), (33,22),
    (8,23), (9,23), (21,23), (26,23), (27,23), (32,23), (33,23),
    (1,24), (21,24), (26,24), (27,24), (31,24), (33,24),
    (1,25), (8,25), (13,25), (14,25), (20,25), (30,25), (31,25), (32,25), (33,25),
    (5,26), (20,26), (25,26), (32,26), (33,26),
    (20,27), (25,27), (32,27), (33,27),
    (15,28), (23,28), (25,28), (29,28), (30,28), (31,28), (32,28), (33,28),
]

VISIBLE_CELLS_SET = set(VISIBLE_CELLS)

# ── Tableau mechanics ─────────────────────────────────────────────────────────

def tableau_body_value(col: int, row: int) -> str:
    """Get the KA-tableau letter at grid position (col, row) [1-based].

    Row 1 = header (' ABCDE...')
    Rows 2-27 = body rows for key letters A-Z
    Row 28 = footer (' ABCDE...')
    Col 1 = row label
    Cols 2-27 = body (KA alphabet shifted by row index 0-25)
    Cols 28-33 = cyclic extension (same as cols 2-7 cyclically)

    Body formula: value = KA[(col - 2 + row - 2) mod 26]
    for body rows (2 <= row <= 27) and body cols (2 <= col)
    """
    if row < 2 or row > 27:
        return " "  # header/footer
    if col == 1:
        return AZ[row - 2]  # row label
    body_col = col - 2
    body_row = row - 2
    return KA[(body_col + body_row) % 26]

def used_tableau_cell_vig(k4_pos: int) -> Tuple[int, int]:
    """For Vigenère, which (col, row) [1-based] tableau cell is used at K4 pos i?

    cell_letter = CT[i] (ciphertext letter produced)
    key_letter K = key[i] (KA body row = AZ.index(K) + 2)
    Column: the col in row K where body value = CT[i]
    body[col-2] = KA[(col-2 + row-2) mod 26] = CT[i]
    -> col-2 = (KA.index(CT[i]) - (row-2)) mod 26
    -> col = (KA.index(CT[i]) - AZ.index(key)) mod 26 + 2
    """
    key_val = CRIB_KEYS_VIG.get(k4_pos)
    if key_val is None:
        return (-1, -1)
    key_letter = AZ[key_val]
    ct_letter = CT_K4[k4_pos]
    row = AZ_IDX[key_letter] + 2  # 1-based
    body_col = (KA_IDX[ct_letter] - AZ_IDX[key_letter]) % 26
    col = body_col + 2  # 1-based
    return (col, row)

def used_tableau_cell_beau(k4_pos: int) -> Tuple[int, int]:
    """For Beaufort: CT[i] = (key[i] - PT[i]) mod 26 in AZ.
    In tableau: looking up by key letter, finding CT letter.
    Same formula as Vigenère but with Beaufort key values.
    """
    key_val = CRIB_KEYS_BEAU.get(k4_pos)
    if key_val is None:
        return (-1, -1)
    key_letter = AZ[key_val]
    ct_letter = CT_K4[k4_pos]
    row = AZ_IDX[key_letter] + 2
    body_col = (KA_IDX[ct_letter] - AZ_IDX[key_letter]) % 26
    col = body_col + 2
    return (col, row)

def grille_hole_ct_value(col: int, row: int) -> str:
    """Given a grille hole at (col, row), what CT value would 'use' this cell?

    For a hole at (col, row) [1-based], the tableau body value is:
      letter = KA[(col-2 + row-2) mod 26]
    This letter would be the CT letter for any K4 position where the
    encryption path passes through this cell.
    """
    if row < 2 or row > 27 or col < 2:
        return ""
    return KA[(col - 2 + row - 2) % 26]

def reachable_keys_for_ct(ct_letter: str) -> List[int]:
    """Which key values (0-25) would cause CT letter to pass through a grille hole?

    For Vigenère: given CT[i] = ct_letter, for each grille hole (col, row),
    the key value that places (col, row) on the encryption path is:
      key_val = AZ_IDX[row_letter]  where row_letter = AZ[row-2]
      And: KA[(col-2 + row-2) mod 26] = ct_letter
      -> (col-2 + row-2) mod 26 = KA_IDX[ct_letter]
      -> col-2 = (KA_IDX[ct_letter] - row + 2) mod 26
      -> col = (KA_IDX[ct_letter] - row + 4) mod 26 + 2  [but col must be >= 2]

    So for each body row r (2..27), the specific col that would encode ct_letter is:
      col = (KA_IDX[ct_letter] - (r-2)) mod 26 + 2

    If that (col, r) pair is in VISIBLE_CELLS, then key_val = r-2 is reachable.
    """
    ct_ka_idx = KA_IDX.get(ct_letter, -1)
    if ct_ka_idx < 0:
        return []
    reachable = []
    for r in range(2, 28):  # body rows 2-27 (key A-Z)
        body_row = r - 2
        col = (ct_ka_idx - body_row) % 26 + 2
        if (col, r) in VISIBLE_CELLS_SET:
            reachable.append(body_row)  # key val = AZ index of key letter
    return reachable

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print(f"  {EXPERIMENT_ID}: Tableau Cell Correspondence Model — Analytical Check")
    print("=" * 72)
    sys.stdout.flush()

    # ── Part 1: Verify 1/24 crib cell hit rate ────────────────────────────────
    print("\n" + "─" * 72)
    print("Part 1: Verify 'grille marks used tableau cells' model")
    print("─" * 72)

    print("\nVigenère: (col, row) of used tableau cell for each crib position")
    print(f"  {'K4[i]':>6s} {'key':>4s} {'CT':>3s} {'PT':>3s} {'col':>4s} {'row':>4s} {'in_grille':>10s}")
    vig_hits = 0
    for pos in sorted(CRIB_KEYS_VIG.keys()):
        col, row = used_tableau_cell_vig(pos)
        in_g = (col, row) in VISIBLE_CELLS_SET
        if in_g:
            vig_hits += 1
        key_letter = AZ[CRIB_KEYS_VIG[pos]]
        ct_letter = CT_K4[pos]
        pt_letter = CRIB_PT.get(pos, '?')
        print(f"  K4[{pos:2d}] {key_letter:>4s} {ct_letter:>3s} {pt_letter:>3s} {col:>4d} {row:>4d} {'YES ***' if in_g else 'no':>10s}")

    expected = 107 / (28 * 33)  # fraction of cells that are holes
    expected_hits = 24 * expected
    print(f"\n  Vig hits: {vig_hits}/24 (expected under random: {expected_hits:.1f})")
    print(f"  CONCLUSION: 'Grille marks used tableau cells' model {'COMPATIBLE' if vig_hits >= 10 else 'ELIMINATED'}")
    print(f"    ({vig_hits}/{24} << expected {expected_hits:.1f} -> strong elimination)")

    # Beaufort
    print("\nBeaufort: used tableau cell hits")
    beau_hits = 0
    for pos in sorted(CRIB_KEYS_BEAU.keys()):
        col, row = used_tableau_cell_beau(pos)
        in_g = (col, row) in VISIBLE_CELLS_SET
        if in_g:
            beau_hits += 1
    print(f"  Beau hits: {beau_hits}/24 (expected: {expected_hits:.1f})")

    # ── Part 2: NOVEL — Grille hole → CT coverage map ────────────────────────
    print("\n" + "─" * 72)
    print("Part 2: NOVEL — Which CT letters can each grille hole 'serve'?")
    print("─" * 72)

    # For each hole, compute the CT letter it would encode
    hole_ct_map: Dict[Tuple[int,int], str] = {}
    for col, row in VISIBLE_CELLS:
        letter = grille_hole_ct_value(col, row)
        if letter:
            hole_ct_map[(col, row)] = letter

    # Count: for each letter, how many grille holes could produce it
    from collections import Counter
    hole_ct_dist = Counter(hole_ct_map.values())

    print("\nCT letter -> number of grille holes that can 'produce' that CT letter:")
    print(f"  {'CT':>3s} {'Holes':>5s}  {'Positions in K4 with this CT'}")
    for letter in AZ:
        n_holes = hole_ct_dist.get(letter, 0)
        k4_positions = [i for i, c in enumerate(CT_K4) if c == letter]
        star = " ***" if n_holes == 0 else ""
        print(f"  {letter:>3s} {n_holes:5d}  {k4_positions}{star}")

    # ── Part 3: NOVEL — Reachable key values per K4 position ─────────────────
    print("\n" + "─" * 72)
    print("Part 3: NOVEL — Reachable key values from grille holes per K4 position")
    print("─" * 72)
    print("(For each K4 position, what key values are reachable from any grille hole?)")
    print("(Checks if known crib key values are 'grille-reachable')")
    print()
    print(f"  {'K4[i]':>6s} {'CT':>3s} {'Reachable_keys (0-25)':>30s} {'Crib_key':>9s} {'Reachable?':>10s}")

    crib_reachable_count = 0
    non_crib_reachable_total = 0
    non_crib_count = 0

    for i, ct_ch in enumerate(CT_K4):
        reachable = reachable_keys_for_ct(ct_ch)
        n_reachable = len(reachable)
        if i in CRIB_KEYS_VIG:
            crib_key = CRIB_KEYS_VIG[i]
            is_reachable = crib_key in reachable
            if is_reachable:
                crib_reachable_count += 1
            print(f"  K4[{i:2d}] {ct_ch:>3s} {str(reachable)[:30]:>30s} {AZ[crib_key]:>9s} "
                  f"{'YES' if is_reachable else 'NO ***':>10s}")
        else:
            non_crib_reachable_total += n_reachable
            non_crib_count += 1

    print(f"\n  Crib positions with grille-reachable key: {crib_reachable_count}/24")
    avg_reachable_non_crib = non_crib_reachable_total / max(1, non_crib_count)
    print(f"  Average reachable key values for non-crib positions: {avg_reachable_non_crib:.1f}/26")

    if crib_reachable_count < 24:
        print(f"\n  *** {24 - crib_reachable_count} crib positions have NO grille-reachable key value ***")
        print("  Implication: Any grille-based SINGLE-STEP tableau-lookup key model is ELIMINATED.")
        print("  Multi-step or indirect models (e.g., grille → intermediate → K4) remain open.")
    else:
        print("\n  All 24 crib positions have at least one grille-reachable key value.")
        print("  Implication: Grille-based tableau-lookup model is COMPATIBLE with cribs.")
        print("  Further investigation warranted.")

    # ── Part 4: CT distribution vs grille-reachable distribution ─────────────
    print("\n" + "─" * 72)
    print("Part 4: CT coverage completeness")
    print("─" * 72)

    ct_letters_in_k4 = set(CT_K4)
    ct_letters_covered = set(c for c in ct_letters_in_k4 if hole_ct_dist.get(c, 0) > 0)
    ct_letters_uncovered = ct_letters_in_k4 - ct_letters_covered

    print(f"\nDistinct CT letters in K4: {sorted(ct_letters_in_k4)}")
    print(f"Letters with at least 1 grille hole coverage: {sorted(ct_letters_covered)}")
    if ct_letters_uncovered:
        print(f"Letters with ZERO grille coverage: {sorted(ct_letters_uncovered)} *** BLOCKING ***")
        for letter in sorted(ct_letters_uncovered):
            k4_positions = [i for i, c in enumerate(CT_K4) if c == letter]
            print(f"  {letter}: appears at K4 positions {k4_positions}")
    else:
        print("All CT letters have at least 1 grille hole.")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY & IMPLICATIONS")
    print("=" * 72)

    print(f"""
1. 'Grille marks used tableau cells' model:
   Vigenère: {vig_hits}/24 hits (expected ~{expected_hits:.1f}). ELIMINATED.
   Beaufort: {beau_hits}/24 hits. ELIMINATED.

2. Grille-reachable keystream:
   For each CT letter in K4, some key values are reachable from grille holes.
   Crib positions with reachable key: {crib_reachable_count}/24.
   {'COMPATIBLE — further work warranted.' if crib_reachable_count == 24 else 'INCOMPATIBLE — some cribs blocked.'}

3. The Cardan grille's primary action (via VISIBLE_CELLS) on the KA tableau
   does NOT directly correspond to K4's encryption path.
   This strongly suggests the grille serves a DIFFERENT function:
   - Source selection (what text to key FROM)
   - Positional indicator (which positions to process)
   - Multi-step: grille -> intermediate text -> final key
   These remain OPEN for investigation.

Recommended next: E-GRILLE-09 (permutation key search) and E-GRILLE-10
(K1-K3 PT as grille source) to explore the remaining open hypotheses.
""")

    print(f"{EXPERIMENT_ID} complete")


if __name__ == "__main__":
    main()
