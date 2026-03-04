#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-AUDIT-05: Test Kryptos tableau columns as decryption keys for K4.

The Kryptos tableau has:
  - Header row: ABCDEFGHIJKLMNOPQRSTUVWXYZ (standard order)
  - Body rows A-Z: each is the KA alphabet shifted by one position
    Row A: KRYPTOSABCDEFGHIJLMNQUVWXZ
    Row B: RYPTOSABCDEFGHIJLMNQUVWXZK
    ...etc (cyclic left-shift of KA alphabet)

We extract each column (0-25) by reading down all 26 body rows,
producing a 26-letter sequence. Then we test each column as:

  1. Periodic Vigenere key (period 26) -- all 3 variants
  2. Simple substitution alphabet (column maps A->col[0], B->col[1], etc.)
  3. Transposition key (rank ordering applied cyclically)

Focus columns: header='L' (index 11) and index 12 (header='M').
Also sweep all 26 columns to find best crib scores.

Usage:
    PYTHONPATH=src python3 -u scripts/e_audit_05_tableau_column_keys.py
"""
from __future__ import annotations

import json
import os
import sys
from typing import List, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN,
)


# ── Build the Kryptos Tableau ──────────────────────────────────────────────

KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def build_tableau() -> List[str]:
    """Build 26 body rows of the Kryptos tableau.

    Row i is KA rotated left by i positions.
    Row 0 (row 'A'): KRYPTOSABCDEFGHIJLMNQUVWXZ
    Row 1 (row 'B'): RYPTOSABCDEFGHIJLMNQUVWXZK
    ...
    """
    rows = []
    for i in range(26):
        row = KA[i:] + KA[:i]
        rows.append(row)
    return rows


def extract_column(tableau: List[str], col_idx: int) -> str:
    """Extract a column from the tableau (reading down all 26 rows)."""
    return "".join(row[col_idx] for row in tableau)


# ── Decryption Methods ─────────────────────────────────────────────────────

def decrypt_vig_periodic(ct: str, key_str: str, variant: CipherVariant) -> str:
    """Decrypt using a letter key as a periodic Vigenere/Beaufort key.

    Key letters are converted to numeric values (A=0, B=1, ..., Z=25)
    using standard alphabet indexing, then applied cyclically.
    """
    key_nums = [ALPH_IDX[c] for c in key_str]
    return decrypt_text(ct, key_nums, variant)


def decrypt_vig_periodic_ka(ct: str, key_str: str, variant: CipherVariant) -> str:
    """Same but key letters indexed by KA alphabet position."""
    ka_idx = {c: i for i, c in enumerate(KA)}
    key_nums = [ka_idx[c] for c in key_str]
    return decrypt_text(ct, key_nums, variant)


def decrypt_simple_sub(ct: str, column: str) -> str:
    """Simple substitution: column defines mapping from standard alphabet.

    column[i] = what letter i (A=0, B=1, ...) maps TO in the cipher alphabet.
    To decrypt: find each CT letter in the column, return its index as a letter.
    """
    # Build reverse mapping: for each letter in column, what index is it at?
    reverse = {}
    for i, ch in enumerate(column):
        if ch not in reverse:  # first occurrence wins
            reverse[ch] = i

    result = []
    for c in ct:
        if c in reverse:
            result.append(ALPH[reverse[c]])
        else:
            result.append('?')
    return "".join(result)


def decrypt_simple_sub_forward(ct: str, column: str) -> str:
    """Simple substitution: column[i] is what letter i decrypts to.

    For each CT char c, find its standard index i, output column[i].
    This treats the column as a direct decryption substitution alphabet.
    """
    result = []
    for c in ct:
        idx = ALPH_IDX[c]
        result.append(column[idx])
    return "".join(result)


def make_transposition_key(column: str) -> List[int]:
    """Convert column letters to a transposition permutation by ranking.

    Sort the letters alphabetically (stable sort preserves order for ties),
    then the rank of each position becomes the permutation index.
    """
    indexed = [(ch, i) for i, ch in enumerate(column)]
    indexed.sort(key=lambda x: x[0])
    perm = [0] * len(column)
    for rank, (ch, orig_idx) in enumerate(indexed):
        perm[orig_idx] = rank
    return perm


def apply_cyclic_transposition(ct: str, perm: List[int]) -> str:
    """Apply a transposition permutation cyclically to text.

    For each block of len(perm) characters, apply the permutation.
    output[perm[i]] = input[i] within each block (scatter convention).
    Then invert to get gather convention: output[i] = input[inv_perm[i]].
    """
    n = len(perm)
    # Invert permutation for gather
    inv_perm = [0] * n
    for i, p in enumerate(perm):
        inv_perm[p] = i

    result = list(ct)
    for block_start in range(0, len(ct), n):
        block_end = min(block_start + n, len(ct))
        block_len = block_end - block_start
        block = ct[block_start:block_end]
        for i in range(block_len):
            if inv_perm[i] < block_len:
                result[block_start + i] = block[inv_perm[i]]
    return "".join(result)


def apply_cyclic_transposition_gather(ct: str, perm: List[int]) -> str:
    """Apply transposition in gather convention: output[i] = input[perm[i]].

    Applied cyclically in blocks of len(perm).
    """
    n = len(perm)
    result = list(ct)
    for block_start in range(0, len(ct), n):
        block_end = min(block_start + n, len(ct))
        block_len = block_end - block_start
        block = ct[block_start:block_end]
        for i in range(block_len):
            if perm[i] < block_len:
                result[block_start + i] = block[perm[i]]
    return "".join(result)


# ── Scoring helper ─────────────────────────────────────────────────────────

def quick_score(pt: str) -> Tuple[int, dict]:
    """Quick crib score + detail."""
    detail = score_cribs_detailed(pt)
    return detail["score"], detail


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("E-AUDIT-05: Kryptos Tableau Column Keys")
    print("=" * 80)
    print()

    # Build tableau
    tableau = build_tableau()

    print("Kryptos Tableau (first 5 rows shown):")
    print(f"  Header: {ALPH}")
    for i in range(5):
        print(f"  Row {ALPH[i]}:  {tableau[i]}")
    print(f"  ...")
    print()

    # Extract and display all columns
    columns = {}
    for col_idx in range(26):
        col_str = extract_column(tableau, col_idx)
        columns[col_idx] = col_str

    # Show focus columns
    print("Focus Columns:")
    print(f"  Column 11 (header='L'): {columns[11]}")
    print(f"  Column 12 (header='M'): {columns[12]}")
    print()

    print("All 26 columns:")
    for idx in range(26):
        print(f"  Col {idx:2d} (header='{ALPH[idx]}'): {columns[idx]}")
    print()

    # ── Test all methods across all columns ────────────────────────────────

    all_results = []

    for col_idx in range(26):
        col = columns[col_idx]
        header_letter = ALPH[col_idx]

        # 1. Periodic Vigenere key (period 26) -- 3 variants x 2 indexing schemes
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            for indexing, decrypt_fn in [("AZ-indexed", decrypt_vig_periodic),
                                          ("KA-indexed", decrypt_vig_periodic_ka)]:
                pt = decrypt_fn(CT, col, variant)
                sc, detail = quick_score(pt)
                ic_val = ic(pt)
                desc = f"Col {col_idx:2d} ({header_letter}) | {variant.value:14s} | {indexing}"
                all_results.append((sc, ic_val, desc, pt, detail))

        # 2. Simple substitution (two directions)
        pt_rev = decrypt_simple_sub(CT, col)
        sc, detail = quick_score(pt_rev)
        ic_val = ic(pt_rev)
        desc = f"Col {col_idx:2d} ({header_letter}) | sub_reverse     | find CT in col"
        all_results.append((sc, ic_val, desc, pt_rev, detail))

        pt_fwd = decrypt_simple_sub_forward(CT, col)
        sc, detail = quick_score(pt_fwd)
        ic_val = ic(pt_fwd)
        desc = f"Col {col_idx:2d} ({header_letter}) | sub_forward     | col[CT_idx]"
        all_results.append((sc, ic_val, desc, pt_fwd, detail))

        # 3. Transposition key (two conventions)
        perm = make_transposition_key(col)
        pt_scatter = apply_cyclic_transposition(CT, perm)
        sc, detail = quick_score(pt_scatter)
        ic_val = ic(pt_scatter)
        desc = f"Col {col_idx:2d} ({header_letter}) | trans_scatter   | cyclic perm"
        all_results.append((sc, ic_val, desc, pt_scatter, detail))

        pt_gather = apply_cyclic_transposition_gather(CT, perm)
        sc, detail = quick_score(pt_gather)
        ic_val = ic(pt_gather)
        desc = f"Col {col_idx:2d} ({header_letter}) | trans_gather    | cyclic perm"
        all_results.append((sc, ic_val, desc, pt_gather, detail))

    # ── Sort by score and display ──────────────────────────────────────────

    all_results.sort(key=lambda x: (-x[0], -x[1]))

    print("=" * 80)
    print("TOP 30 RESULTS (sorted by crib score)")
    print("=" * 80)
    print()

    for i, (sc, ic_val, desc, pt, detail) in enumerate(all_results[:30]):
        ene = detail["ene_score"]
        bc = detail["bc_score"]
        print(f"  #{i+1:3d}: score={sc:2d}/24 (ENE={ene:2d} BC={bc:2d}) IC={ic_val:.4f} | {desc}")
        # Show plaintext with crib regions highlighted
        pt_display = pt[:21] + "[" + pt[21:34] + "]" + pt[34:63] + "[" + pt[63:74] + "]" + pt[74:]
        print(f"        PT: {pt_display}")
        if sc >= 3:
            matched = detail["matched_positions"]
            print(f"        Matched positions: {matched}")
        print()

    # ── Focus analysis on the L column specifically ────────────────────────

    print("=" * 80)
    print("DETAILED ANALYSIS: Column 11 (header='L') and Column 12 (header='M')")
    print("=" * 80)
    print()

    for focus_idx in [11, 12]:
        col = columns[focus_idx]
        header_letter = ALPH[focus_idx]

        print(f"--- Column {focus_idx} (header='{header_letter}') ---")
        print(f"  Column letters: {col}")
        print(f"  Numeric (AZ):   {[ALPH_IDX[c] for c in col]}")
        ka_idx_map = {c: i for i, c in enumerate(KA)}
        print(f"  Numeric (KA):   {[ka_idx_map[c] for c in col]}")
        print()

        # Show all decryptions for this column
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            for indexing, decrypt_fn in [("AZ", decrypt_vig_periodic),
                                          ("KA", decrypt_vig_periodic_ka)]:
                pt = decrypt_fn(CT, col, variant)
                sc, detail = quick_score(pt)
                ic_val = ic(pt)
                ene = detail["ene_score"]
                bc = detail["bc_score"]
                print(f"  {variant.value:14s} ({indexing}): score={sc:2d}/24 (ENE={ene} BC={bc}) IC={ic_val:.4f}")
                print(f"    PT: {pt}")
                if sc > 0:
                    print(f"    Matched: {detail['matched_positions']}")
                print()

        # Substitution
        for label, pt in [("sub_reverse", decrypt_simple_sub(CT, col)),
                          ("sub_forward", decrypt_simple_sub_forward(CT, col))]:
            sc, detail = quick_score(pt)
            ic_val = ic(pt)
            print(f"  {label:14s}:       score={sc:2d}/24 (ENE={detail['ene_score']} BC={detail['bc_score']}) IC={ic_val:.4f}")
            print(f"    PT: {pt}")
            if sc > 0:
                print(f"    Matched: {detail['matched_positions']}")
            print()

        # Transposition
        perm = make_transposition_key(col)
        print(f"  Transposition perm: {perm}")
        for label, pt in [("scatter", apply_cyclic_transposition(CT, perm)),
                          ("gather", apply_cyclic_transposition_gather(CT, perm))]:
            sc, detail = quick_score(pt)
            ic_val = ic(pt)
            print(f"  trans_{label:7s}:       score={sc:2d}/24 (ENE={detail['ene_score']} BC={detail['bc_score']}) IC={ic_val:.4f}")
            print(f"    PT: {pt}")
            if sc > 0:
                print(f"    Matched: {detail['matched_positions']}")
            print()
        print()

    # ── Additional: try the column as a running key (non-repeating, just 26 chars) ──

    print("=" * 80)
    print("BONUS: Column as running key (first 26 chars only, then identity)")
    print("=" * 80)
    print()

    for focus_idx in [11, 12]:
        col = columns[focus_idx]
        header_letter = ALPH[focus_idx]

        # Use column for first 26 chars, then shift=0 for remaining
        key_nums_az = [ALPH_IDX[c] for c in col] + [0] * (CT_LEN - 26)
        key_nums_ka = [ka_idx_map[c] for c in col] + [0] * (CT_LEN - 26)

        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            for label, key_nums in [("AZ", key_nums_az), ("KA", key_nums_ka)]:
                pt = decrypt_text(CT, key_nums, variant)
                sc, detail = quick_score(pt)
                print(f"  Col {focus_idx} ({header_letter}) | {variant.value:14s} | {label} running: "
                      f"score={sc:2d}/24 (ENE={detail['ene_score']} BC={detail['bc_score']})")
                print(f"    PT: {pt}")
        print()

    # ── Additional: use column repeated + offset by row ───────────────────

    print("=" * 80)
    print("BONUS: Column with offset (shift column start by 0-25)")
    print("=" * 80)
    print()

    best_offset_results = []

    for focus_idx in [11, 12]:
        col = columns[focus_idx]
        header_letter = ALPH[focus_idx]

        for offset in range(26):
            shifted_col = col[offset:] + col[:offset]
            key_nums = [ALPH_IDX[c] for c in shifted_col]

            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(CT, key_nums, variant)
                sc, detail = quick_score(pt)
                if sc >= 2:
                    best_offset_results.append((
                        sc, focus_idx, header_letter, offset, variant.value,
                        detail["ene_score"], detail["bc_score"], pt
                    ))

    best_offset_results.sort(key=lambda x: -x[0])

    if best_offset_results:
        print(f"  Results with score >= 2 (from offset search):")
        for sc, cidx, hl, off, var, ene, bc, pt in best_offset_results[:20]:
            print(f"    Col {cidx} ({hl}) offset={off:2d} {var:14s}: score={sc}/24 (ENE={ene} BC={bc})")
            print(f"      PT: {pt}")
        print()
    else:
        print("  No results with score >= 2 from offset search.")
        print()

    # ── Summary statistics ─────────────────────────────────────────────────

    print("=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print()

    scores = [r[0] for r in all_results]
    from collections import Counter
    score_dist = Counter(scores)

    print(f"  Total configurations tested: {len(all_results)}")
    print(f"  + offset variations: {len(best_offset_results)} had score >= 2")
    print(f"  Score distribution:")
    for sc_val in sorted(score_dist.keys(), reverse=True):
        print(f"    Score {sc_val:2d}: {score_dist[sc_val]:4d} configs")
    print()

    max_score = max(scores)
    print(f"  Best score: {max_score}/24")
    if max_score > 0:
        print(f"  Best configs:")
        for sc, ic_val, desc, pt, detail in all_results:
            if sc == max_score:
                print(f"    {desc}")
                print(f"      PT: {pt}")
                print(f"      Matched: {detail['matched_positions']}")

    print()
    print(f"  Noise floor: 6/24. Maximum seen: {max_score}/24.")
    if max_score <= 6:
        print(f"  CONCLUSION: All results at or below noise floor. No signal detected.")
    elif max_score <= 10:
        print(f"  CONCLUSION: Marginal results, likely noise for period 26.")
    else:
        print(f"  CONCLUSION: Scores above noise -- investigate further!")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
