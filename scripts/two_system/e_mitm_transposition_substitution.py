#!/usr/bin/env python3
# Cipher: product (transposition × substitution)
# Family: two_system
# Status: active
# Keyspace: columnar transposition (widths 4-14) × periodic Vig/Beau/VBeau (periods 1-14)
# Last run:
# Best score:
#
# Meet-in-the-Middle Attack on K4's Two-System Cipher
#
# Based on Stinson's product cipher theory: if K4 = substitution(transposition(PT)),
# then the intermediate text IT = transposition(PT), and CT = substitution(IT).
#
# KEY INSIGHT (digram test, 2026-03-11): K4's digrams are essentially random (5.2%
# match English top-30, vs 42% expected for transposition). This proves the OUTERMOST
# layer is substitution. Encryption order: PT → transposition → substitution → CT.
#
# MITM DECOMPOSITION:
#   Forward:  For each transposition T, compute what intermediate values are needed
#             at the positions where T maps crib positions. These must equal T(PT)[j]
#             for crib positions i where T maps i→j.
#   Backward: For each substitution key K, compute undo_sub(CT, K) = intermediate.
#   Meet:     Find (T, K) where the intermediate matches at all 24 crib-mapped positions.
#
# For columnar transposition with width W:
#   - PT is written into rows of width W, then columns are read in some order
#   - So PT[i] → IT[column_position(i)] where column_position is determined by the
#     permutation and the grid layout
#   - We know PT[i] for 24 crib positions i
#   - We know IT[j] = undo_sub(CT[j], K) for all j
#   - Match: IT[T(i)] = undo_sub(CT[T(i)], K) must equal PT[i] for all crib i
#
# This is more subtle than standard MITM because the transposition maps POSITIONS,
# not values. We can't just hash intermediate values — we need to check consistency
# at specific mapped positions.
#
# EFFICIENT APPROACH:
#   For each transposition T:
#     - Compute where each crib position maps: mapped_pos[i] = T(i) for crib positions
#     - For each crib position i: CT[T(i)] and PT[i] are known
#     - Derive the required key value at each mapped position:
#       k[T(i)] = (CT[T(i)] - PT[i]) mod 26  (Vigenère)
#     - If substitution has period p: all T(i) with T(i) mod p = r must have same k
#     - Check consistency of derived key values per residue class
#   This avoids iterating over all keys! The cribs directly constrain the key.
#
# Usage: PYTHONPATH=src python3 -u scripts/two_system/e_mitm_transposition_substitution.py

from __future__ import annotations

import math
import sys
import time
import json
from collections import defaultdict
from itertools import permutations
from typing import List, Tuple, Dict, Optional, Set

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ── Columnar transposition position mapping ────────────────────────────────

def columnar_encrypt_positions(length: int, col_order: List[int]) -> List[int]:
    """Compute the position mapping for columnar transposition encryption.

    Given plaintext of `length` chars written into rows of width=len(col_order),
    columns read in col_order, returns mapping where result[i] = j means
    PT position i maps to intermediate position j.

    Encryption: write PT into grid row by row, read columns in col_order.
    """
    ncols = len(col_order)
    nrows = math.ceil(length / ncols)
    total = nrows * ncols
    short_cols = total - length

    # Which columns are short (have nrows-1 chars)?
    # Convention: last `short_cols` columns (in natural order) are short
    col_lengths = []
    for col in range(ncols):
        if col >= ncols - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    # Compute output position for each input position
    # Input: PT[row * ncols + col] (row-major write)
    # Output: columns read in col_order
    #   First: compute starting output position for each column (in read order)
    col_starts = {}
    pos = 0
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        col_starts[col_idx] = pos
        pos += col_lengths[col_idx]

    # Map each PT position to its output position
    mapping = [0] * length
    for i in range(length):
        row = i // ncols
        col = i % ncols
        if row < col_lengths[col]:
            output_pos = col_starts[col] + row
            mapping[i] = output_pos
        # else: this position doesn't exist (padding) — shouldn't happen for i < length

    return mapping


def columnar_decrypt_positions(length: int, col_order: List[int]) -> List[int]:
    """Inverse of columnar_encrypt_positions.

    Returns mapping where result[j] = i means intermediate position j came from
    PT position i. Equivalently, to decrypt: PT[inv[j]] = IT[j].
    """
    fwd = columnar_encrypt_positions(length, col_order)
    inv = [0] * length
    for i, j in enumerate(fwd):
        inv[j] = i
    return inv


def undo_columnar(ct: str, col_order: List[int]) -> str:
    """Undo columnar transposition: CT → intermediate text."""
    ncols = len(col_order)
    nrows = math.ceil(len(ct) / ncols)
    total = nrows * ncols
    short_cols = total - len(ct)

    col_lengths = []
    for col in range(ncols):
        if col >= ncols - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    # Distribute CT into columns in the given order
    grid = [[] for _ in range(ncols)]
    pos = 0
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        length = col_lengths[col_idx]
        grid[col_idx] = list(ct[pos:pos + length])
        pos += length

    # Read rows
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return "".join(result)


def do_columnar(pt: str, col_order: List[int]) -> str:
    """Apply columnar transposition: PT → CT."""
    ncols = len(col_order)
    nrows = math.ceil(len(pt) / ncols)
    total = nrows * ncols

    # Write PT into grid row by row
    grid = []
    for row in range(nrows):
        grid.append(list(pt[row * ncols: (row + 1) * ncols]))

    # Read columns in col_order
    result = []
    for order_idx in range(ncols):
        col_idx = col_order[order_idx]
        for row in range(nrows):
            if col_idx < len(grid[row]):
                result.append(grid[row][col_idx])
    return "".join(result)


# ── Substitution helpers ───────────────────────────────────────────────────

def derive_key_vig(ct_char: str, pt_char: str) -> int:
    """Vigenère: k = (CT - PT) mod 26."""
    return (ALPH_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD

def derive_key_beau(ct_char: str, pt_char: str) -> int:
    """Beaufort: k = (CT + PT) mod 26."""
    return (ALPH_IDX[ct_char] + ALPH_IDX[pt_char]) % MOD

def derive_key_vbeau(ct_char: str, pt_char: str) -> int:
    """Variant Beaufort: k = (PT - CT) mod 26."""
    return (ALPH_IDX[pt_char] - ALPH_IDX[ct_char]) % MOD

def decrypt_vig(ct_char: str, key_val: int) -> str:
    """Decrypt single char with Vigenère key."""
    return ALPH[(ALPH_IDX[ct_char] - key_val) % MOD]

def decrypt_beau(ct_char: str, key_val: int) -> str:
    """Decrypt single char with Beaufort key."""
    return ALPH[(key_val - ALPH_IDX[ct_char]) % MOD]

def decrypt_vbeau(ct_char: str, key_val: int) -> str:
    """Decrypt single char with Variant Beaufort key."""
    return ALPH[(ALPH_IDX[ct_char] + key_val) % MOD]

VARIANTS = [
    ("Vig", derive_key_vig, decrypt_vig),
    ("Beau", derive_key_beau, decrypt_beau),
    ("VBeau", derive_key_vbeau, decrypt_vbeau),
]


# ── MITM core ──────────────────────────────────────────────────────────────

def check_transposition_crib_consistency(
    col_order: List[int],
    period: int,
    variant_name: str,
    derive_key_fn,
    decrypt_fn,
) -> Tuple[int, Optional[str], Optional[str]]:
    """For a given transposition and substitution variant+period, check if
    the cribs are consistent.

    Encryption model: PT → columnar_encrypt(col_order) → IT → sub(key, period) → CT
    So: IT = columnar_encrypt(PT), CT = sub(IT, key)
    Decryption: IT = undo_sub(CT, key), PT = undo_columnar(IT)

    From cribs, we know PT at 24 positions. The transposition maps each PT
    position to an IT position. At each IT position j = map[i], we have:
      CT[j] = sub(IT[j], key[j % period]) = sub(PT[i], key[j % period])
    So: key[j % period] = derive_key(CT[j], PT[i])

    For consistency with period p: all crib positions mapping to the same
    residue class (j mod p) must produce the same key value.

    Returns (n_consistent, full_plaintext_or_None, key_description_or_None).
    """
    # Get the position mapping: fwd[i] = j means PT[i] → IT[j]
    fwd = columnar_encrypt_positions(CT_LEN, col_order)

    # For each crib position, compute mapped position and required key
    residue_keys: Dict[int, Set[int]] = defaultdict(set)
    crib_mapped = []  # (pt_pos, it_pos, pt_char, ct_at_it_pos, derived_key)

    for pt_pos in sorted(CRIB_POSITIONS):
        it_pos = fwd[pt_pos]
        pt_char = CRIB_DICT[pt_pos]
        ct_char = CT[it_pos]
        key_val = derive_key_fn(ct_char, pt_char)
        residue = it_pos % period
        residue_keys[residue].add(key_val)
        crib_mapped.append((pt_pos, it_pos, pt_char, ct_char, key_val))

    # Count consistent positions
    # A residue class is consistent if all crib positions mapping to it have same key
    n_consistent = 0
    n_total = 0
    key_by_residue: Dict[int, int] = {}
    conflicted_residues: Set[int] = set()

    for residue, keys in residue_keys.items():
        n_in_class = sum(1 for _, it_pos, _, _, _ in crib_mapped if it_pos % period == residue)
        if len(keys) == 1:
            n_consistent += n_in_class
            key_by_residue[residue] = next(iter(keys))
        else:
            conflicted_residues.add(residue)
            # Count the majority key as "consistent"
            key_counts: Dict[int, int] = defaultdict(int)
            for _, it_pos, _, _, kv in crib_mapped:
                if it_pos % period == residue:
                    key_counts[kv] += 1
            best_key = max(key_counts, key=key_counts.get)
            n_consistent += key_counts[best_key]
            # Don't add to key_by_residue — conflicted

    if n_consistent < N_CRIBS:
        return n_consistent, None, None

    # Full consistency! Reconstruct key and decrypt
    # Build full key (period p)
    key = [0] * period
    for r, kv in key_by_residue.items():
        key[r] = kv
    # For residues without crib constraints, key is unknown — use 0 (will produce wrong PT)

    # Decrypt: undo substitution, then undo transposition
    intermediate = []
    for j in range(CT_LEN):
        r = j % period
        intermediate.append(decrypt_fn(CT[j], key[r]))
    intermediate_text = "".join(intermediate)

    # Undo transposition
    plaintext = undo_columnar(intermediate_text, col_order)

    # Build key description
    key_chars = "".join(ALPH[k] for k in key)
    desc = f"{variant_name} p={period} key={key_chars} cols={col_order}"

    return n_consistent, plaintext, desc


def keyword_to_col_order(keyword: str, width: int) -> List[int]:
    """Convert keyword to column read order."""
    kw = keyword[:width] if len(keyword) >= width else (keyword * ((width // len(keyword)) + 1))[:width]
    return sorted(range(width), key=lambda i: (kw[i], i))


# ── Thematic keywords ──────────────────────────────────────────────────────

THEMATIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "ENIGMA", "COMPASS", "KOMPASS", "DEFECTOR",
    "COLOPHON", "BERLIN", "CLOCK", "FIVE", "POINT", "LUCID",
    "MEMORY", "FORCES", "DIGITAL", "INVISIBLE", "POSITION",
    "MATRIX", "CIPHER", "SECRET", "QUAGMIRE", "VERDIGRIS",
    "GNOMON", "OCULUS", "TRIPTYCH", "ARMATURE", "DOLMEN",
    "FILIGREE", "PARALLAX", "CENOTAPH", "OUBLIETTE",
    "ESCUTCHEON", "DIGETAL", "UNDERGRUUND", "IQLUSION",
    "DESPARATLY", "DYAHR", "NORTHWEST", "NORTHEAST",
    "EASTNORTHEAST", "BERLINCLOCK", "MASQUERADE",
]


# ── Load quadgram scorer ──────────────────────────────────────────────────

def load_quadgrams(path: str = "data/english_quadgrams.json") -> Dict[str, float]:
    """Load quadgram log-probabilities."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def score_quadgrams(text: str, qg: Dict[str, float]) -> float:
    """Score text by average quadgram log-probability."""
    if not qg or len(text) < 4:
        return -15.0
    total = 0.0
    count = 0
    floor = min(qg.values()) - 1.0
    for i in range(len(text) - 3):
        gram = text[i:i+4].upper()
        total += qg.get(gram, floor)
        count += 1
    return total / count if count > 0 else -15.0


# ── Main attack ────────────────────────────────────────────────────────────

def attack():
    print("=" * 80)
    print("MEET-IN-THE-MIDDLE: TRANSPOSITION × SUBSTITUTION")
    print("Model: PT → columnar_transposition → substitution → CT")
    print("=" * 80)
    print(f"\nCT: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions known")
    print()

    # Load quadgrams for scoring full-consistency hits
    qg = load_quadgrams()

    # ── Verify roundtrip ──────────────────────────────────────────────────
    test_order = [2, 0, 3, 1]
    test_text = "HELLOWORLD"
    encrypted = do_columnar(test_text, test_order)
    decrypted = undo_columnar(encrypted, test_order)
    assert decrypted == test_text, f"Roundtrip failed: {test_text} → {encrypted} → {decrypted}"
    print("✓ Columnar transposition roundtrip verified")

    # Verify position mapping consistency
    fwd = columnar_encrypt_positions(len(test_text), test_order)
    for i, ch in enumerate(test_text):
        assert encrypted[fwd[i]] == ch, f"Position mapping failed at {i}: expected {ch} at {fwd[i]}, got {encrypted[fwd[i]]}"
    print("✓ Position mapping verified")
    print()

    # ── Results tracking ──────────────────────────────────────────────────
    top_results: List[Tuple[int, float, str, str]] = []  # (crib_score, qg_score, desc, plaintext)
    total_tested = 0
    t_start = time.time()

    # Score thresholds
    MIN_INTERESTING = 18  # Report configurations with 18+ crib matches

    # ── Brute force widths 4-9 ────────────────────────────────────────────
    for width in range(4, 10):
        n_perms = math.factorial(width)
        t_width = time.time()
        width_best = 0
        width_count = 0

        for perm in permutations(range(width)):
            col_order = list(perm)

            for period in range(1, min(width + 1, 15)):
                for var_name, derive_fn, decrypt_fn in VARIANTS:
                    score, pt, desc = check_transposition_crib_consistency(
                        col_order, period, var_name, derive_fn, decrypt_fn
                    )
                    total_tested += 1
                    width_count += 1

                    if score > width_best:
                        width_best = score

                    if score >= MIN_INTERESTING:
                        qg_score = score_quadgrams(pt, qg) if pt else -15.0
                        top_results.append((score, qg_score, desc, pt or ""))
                        if score >= 24:
                            print(f"\n*** FULL CRIB MATCH! ***")
                            print(f"  {desc}")
                            print(f"  PT: {pt}")
                            print(f"  Quadgram: {qg_score:.4f}")

        elapsed = time.time() - t_width
        print(f"  Width {width}: {width_count:>8,} configs ({n_perms} perms × {min(width, 14)} periods × 3 variants) in {elapsed:.1f}s  best_crib={width_best}")
        sys.stdout.flush()

    # ── Keyword-based widths 10-14 ────────────────────────────────────────
    for width in range(10, 15):
        t_width = time.time()
        width_best = 0
        width_count = 0
        seen_orders = set()

        for keyword in THEMATIC_KEYWORDS:
            # Generate keyword variants
            keywords_to_try = set()

            # Basic truncation/extension
            if len(keyword) >= width:
                keywords_to_try.add(keyword[:width])
            else:
                extended = (keyword * ((width // len(keyword)) + 1))[:width]
                keywords_to_try.add(extended)

            # Rotations
            for start in range(len(keyword)):
                rotated = keyword[start:] + keyword[:start]
                if len(rotated) >= width:
                    keywords_to_try.add(rotated[:width])
                else:
                    ext = (rotated * ((width // len(rotated)) + 1))[:width]
                    keywords_to_try.add(ext)

            for kw in keywords_to_try:
                order = keyword_to_col_order(kw, width)
                order_tuple = tuple(order)

                # Also try inverse
                inv_order = [0] * width
                for i, v in enumerate(order):
                    inv_order[v] = i

                for o in [order, inv_order]:
                    o_tuple = tuple(o)
                    if o_tuple in seen_orders:
                        continue
                    seen_orders.add(o_tuple)

                    for period in range(1, 15):
                        for var_name, derive_fn, decrypt_fn in VARIANTS:
                            score, pt, desc = check_transposition_crib_consistency(
                                list(o), period, var_name, derive_fn, decrypt_fn
                            )
                            total_tested += 1
                            width_count += 1

                            if score > width_best:
                                width_best = score

                            if score >= MIN_INTERESTING:
                                qg_score = score_quadgrams(pt, qg) if pt else -15.0
                                top_results.append((score, qg_score, desc, pt or ""))
                                if score >= 24:
                                    print(f"\n*** FULL CRIB MATCH! ***")
                                    print(f"  {desc}")
                                    print(f"  PT: {pt}")
                                    print(f"  Quadgram: {qg_score:.4f}")

        elapsed = time.time() - t_width
        print(f"  Width {width}: {width_count:>8,} configs ({len(seen_orders)} orders × 14 periods × 3 variants) in {elapsed:.1f}s  best_crib={width_best}")
        sys.stdout.flush()

    # ── Double columnar (K3-style) ────────────────────────────────────────
    print("\n--- Double columnar transposition ---")
    DOUBLE_KEYWORDS = [
        ("KRYPTOS", "ABSCISSA"), ("KRYPTOS", "PALIMPSEST"),
        ("KRYPTOS", "SHADOW"), ("KRYPTOS", "COMPASS"),
        ("KRYPTOS", "KOMPASS"), ("KRYPTOS", "DEFECTOR"),
        ("KRYPTOS", "BERLIN"), ("KRYPTOS", "CLOCK"),
        ("KRYPTOS", "POINT"), ("KRYPTOS", "FIVE"),
        ("ABSCISSA", "PALIMPSEST"), ("ABSCISSA", "SHADOW"),
        ("SHADOW", "COMPASS"), ("SHADOW", "KOMPASS"),
        ("COMPASS", "DEFECTOR"), ("COMPASS", "BERLIN"),
        ("BERLIN", "CLOCK"), ("CLOCK", "POINT"),
        ("SANBORN", "SCHEIDT"), ("SANBORN", "KRYPTOS"),
        ("SCHEIDT", "KRYPTOS"), ("ENIGMA", "KRYPTOS"),
        ("DEFECTOR", "COMPASS"), ("DEFECTOR", "BERLIN"),
        ("COLOPHON", "KRYPTOS"), ("COLOPHON", "BERLIN"),
    ]

    double_count = 0
    double_best = 0
    t_double = time.time()

    for kw1, kw2 in DOUBLE_KEYWORDS:
        for w1 in range(4, 15):
            order1 = keyword_to_col_order(kw1, w1)
            for w2 in range(4, 15):
                order2 = keyword_to_col_order(kw2, w2)

                # Apply double transposition: first trans with order1, then with order2
                # To undo: first undo order2, then undo order1
                intermediate = undo_columnar(CT, order2)
                # Now check crib consistency on this intermediate as if it's
                # sub(trans1(PT)) where trans1 uses order1
                for period in range(1, 15):
                    for var_name, derive_fn, decrypt_fn in VARIANTS:
                        # We need to check: does this intermediate, when treated as
                        # sub(trans1(PT)), have consistent cribs?
                        fwd = columnar_encrypt_positions(CT_LEN, order1)

                        residue_keys: Dict[int, set] = defaultdict(set)
                        for pt_pos in sorted(CRIB_POSITIONS):
                            it_pos = fwd[pt_pos]
                            pt_char = CRIB_DICT[pt_pos]
                            ct_char = intermediate[it_pos]
                            key_val = derive_fn(ct_char, pt_char)
                            residue_keys[it_pos % period].add(key_val)

                        n_consistent = 0
                        for residue, keys in residue_keys.items():
                            n_in_class = sum(1 for pp in CRIB_POSITIONS if fwd[pp] % period == residue)
                            if len(keys) == 1:
                                n_consistent += n_in_class
                            else:
                                key_counts: Dict[int, int] = defaultdict(int)
                                for pp in CRIB_POSITIONS:
                                    if fwd[pp] % period == residue:
                                        key_counts[derive_fn(intermediate[fwd[pp]], CRIB_DICT[pp])] += 1
                                n_consistent += max(key_counts.values())

                        total_tested += 1
                        double_count += 1

                        if n_consistent > double_best:
                            double_best = n_consistent

                        if n_consistent >= MIN_INTERESTING:
                            # Reconstruct plaintext
                            key = [0] * period
                            for r, keys in residue_keys.items():
                                if len(keys) == 1:
                                    key[r] = next(iter(keys))
                            decrypted_inter = []
                            for j in range(CT_LEN):
                                decrypted_inter.append(decrypt_fn(intermediate[j], key[j % period]))
                            pt = undo_columnar("".join(decrypted_inter), order1)
                            qg_score = score_quadgrams(pt, qg)
                            desc = f"double({kw1}/{w1},{kw2}/{w2}) {var_name} p={period}"
                            top_results.append((n_consistent, qg_score, desc, pt))
                            if n_consistent >= 24:
                                print(f"\n*** FULL CRIB MATCH (double) ***")
                                print(f"  {desc}")
                                print(f"  PT: {pt}")
                                print(f"  Quadgram: {qg_score:.4f}")

    elapsed = time.time() - t_double
    print(f"  Double columnar: {double_count:>8,} configs in {elapsed:.1f}s  best_crib={double_best}")

    # ── Summary ───────────────────────────────────────────────────────────
    total_elapsed = time.time() - t_start
    print(f"\n{'=' * 80}")
    print(f"TOTAL: {total_tested:,} configs in {total_elapsed:.1f}s")
    print(f"{'=' * 80}\n")

    # Sort by crib score, then quadgram
    top_results.sort(key=lambda x: (x[0], x[1]), reverse=True)

    if top_results:
        print(f"TOP {min(30, len(top_results))} RESULTS (crib_score ≥ {MIN_INTERESTING}):")
        print("-" * 100)
        for rank, (crib, qg_s, desc, pt) in enumerate(top_results[:30], 1):
            print(f"  #{rank:3d}  crib={crib:2d}/24  qg={qg_s:+.4f}  {desc}")
            if pt:
                print(f"        PT: {pt[:80]}")
        print()

        # Histogram of crib scores
        from collections import Counter
        score_counts = Counter(r[0] for r in top_results)
        print("Crib score distribution (among hits ≥ 18):")
        for s in sorted(score_counts.keys(), reverse=True):
            print(f"  {s:2d}/24: {score_counts[s]:6,} configs")
    else:
        print(f"NO configurations achieved crib score ≥ {MIN_INTERESTING}")

    print()

    # Report best per width
    best_per_width: Dict[int, Tuple] = {}
    for crib, qg_s, desc, pt in top_results:
        # Extract width from description
        if "cols=" in desc:
            cols_str = desc.split("cols=")[1]
            try:
                w = len(eval(cols_str.split("]")[0] + "]"))
            except:
                continue
            if w not in best_per_width or crib > best_per_width[w][0]:
                best_per_width[w] = (crib, qg_s, desc, pt)

    if best_per_width:
        print("BEST PER WIDTH:")
        for w in sorted(best_per_width.keys()):
            crib, qg_s, desc, pt = best_per_width[w]
            print(f"  Width {w:2d}: crib={crib:2d}/24  qg={qg_s:+.4f}  {desc[:70]}")

    print(f"\n{'=' * 80}")
    print("DONE")
    print(f"{'=' * 80}")

    return top_results


if __name__ == "__main__":
    attack()
