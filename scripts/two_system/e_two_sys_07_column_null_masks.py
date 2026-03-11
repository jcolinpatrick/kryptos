#!/usr/bin/env python3
# Cipher:     Two-system Model A (column-based null mask on 28×31 grid)
# Family:     two_system
# Status:     active
# Keyspace:   512 masks × 704 keywords × 6 variants = ~2.2M
# Last run:
# Best score:
#
# E-TWO-SYS-07: Column-based null masks derived from grid structure.
#
# KEY INSIGHT: K4 spans rows 24-27 of the 28×31 grid (starting at col 27).
# The ENE crib (pos 21-33) occupies row 25, columns 17-29.
# The BC crib (pos 63-73) occupies row 26 cols 28-30 and row 27 cols 0-7.
#
# For a column-based null rule, a column can be null ONLY if it contains
# NO crib positions. Analysis shows ONLY columns 8-16 are crib-free.
# That's just 9 columns. Each contributes exactly 3 null positions
# (one per row in rows 25-27; row 24 only has cols 27-30).
#
# So: 2^9 = 512 possible column masks. For 24 nulls: C(9,8)=9 masks.
# For any null count: 512 masks total. ALL testable in seconds.
#
# Bonus: 3 of 5 W positions (20, 48, 74) fall on crib-free columns
# (16, 13, 8). If those columns are null, those W's are nulls!
from __future__ import annotations

import itertools
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)

# ── Grid mapping ─────────────────────────────────────────────────────────

GRID_WIDTH = 31
K4_START_LINEAR = 24 * GRID_WIDTH + 27  # row 24, col 27 = linear 771

def k4_pos_to_grid(p):
    """Map K4 position (0-96) to (row, col) in 28×31 grid."""
    linear = K4_START_LINEAR + p
    return linear // GRID_WIDTH, linear % GRID_WIDTH


# ── Identify crib-free columns ──────────────────────────────────────────

def find_crib_free_columns():
    """Find columns that contain NO crib positions."""
    crib_columns = set()
    for p in CRIB_POSITIONS:
        _, col = k4_pos_to_grid(p)
        crib_columns.add(col)

    all_cols = set()
    for p in range(CT_LEN):
        _, col = k4_pos_to_grid(p)
        all_cols.add(col)

    return sorted(all_cols - crib_columns)


# ── Build null positions from column set ─────────────────────────────────

def columns_to_null_positions(null_cols):
    """Given a set of null columns, return sorted list of K4 null positions."""
    null_col_set = set(null_cols)
    nulls = []
    for p in range(CT_LEN):
        _, col = k4_pos_to_grid(p)
        if col in null_col_set:
            nulls.append(p)
    return nulls


# ── Cipher variants ──────────────────────────────────────────────────────

def vig_dec(c, k): return (c - k) % MOD
def beau_dec(c, k): return (k - c) % MOD
def vbeau_dec(c, k): return (c + k) % MOD

CIPHERS = {"Vig": vig_dec, "Beau": beau_dec, "VBeau": vbeau_dec}

ALPHABETS = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

# ── Cribs ────────────────────────────────────────────────────────────────

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"
CRIB_LIST = sorted(CRIB_DICT.items())


# ── Scoring ──────────────────────────────────────────────────────────────

def decrypt_and_score(null_positions, keyword, cipher_name, alph_name):
    """Remove nulls, decrypt with periodic key, score cribs.

    Returns (mapped_score, free_score, plaintext, reduced_len).
    """
    alph_str, c2i = ALPHABETS[alph_name]
    dec_fn = CIPHERS[cipher_name]

    try:
        kw_indices = [c2i[c] for c in keyword]
    except KeyError:
        return -1, 0, "", 0

    kw_len = len(kw_indices)
    null_set = set(null_positions)

    # Build reduced CT and position mapping
    reduced_ct = []
    orig_to_reduced = {}
    ridx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            reduced_ct.append(CT[i])
            orig_to_reduced[i] = ridx
            ridx += 1

    reduced_len = len(reduced_ct)

    # Decrypt
    pt_chars = []
    for i, ch in enumerate(reduced_ct):
        c_idx = c2i[ch]
        k_idx = kw_indices[i % kw_len]
        p_idx = dec_fn(c_idx, k_idx)
        pt_chars.append(alph_str[p_idx])
    pt = "".join(pt_chars)

    # Mapped crib score
    mapped = 0
    for orig_pos, expected in CRIB_LIST:
        if orig_pos in orig_to_reduced:
            rpos = orig_to_reduced[orig_pos]
            if rpos < len(pt) and pt[rpos] == expected:
                mapped += 1

    # Free crib score
    free = 0
    if CRIB_ENE in pt:
        free += 13
    if CRIB_BC in pt:
        free += 11

    return mapped, free, pt, reduced_len


# ── Load keywords ────────────────────────────────────────────────────────

def load_keywords():
    wordlist_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords_v2.txt'
    )
    words = set()
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                w = line.upper()
                if 3 <= len(w) <= 13 and w.isalpha():
                    words.add(w)

    # Always include priority keywords
    for w in ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
              "SHADOW", "CIPHER", "SECRET", "BERLIN", "CLOCK",
              "PALIMPSEST", "COMPASS", "LODESTONE", "MAGNETIC",
              "ENIGMA", "SANBORN", "SCHEIDT"]:
        words.add(w)

    return sorted(words)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 78)
    print("E-TWO-SYS-07: Column-based null masks on 28×31 grid")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")

    # Map grid positions
    print(f"\nGrid mapping (K4 starts at linear {K4_START_LINEAR}):")
    for p in [0, 20, 21, 33, 34, 48, 62, 63, 73, 74, 96]:
        r, c = k4_pos_to_grid(p)
        label = ""
        if p in CRIB_POSITIONS:
            label = f" ← CRIB ({CT[p]}→{CRIB_DICT.get(p, '?')})"
        elif CT[p] == 'W':
            label = " ← W"
        print(f"  pos {p:2d}: row {r}, col {c:2d}  CT='{CT[p]}'{label}")

    # Find crib-free columns
    crib_free = find_crib_free_columns()
    print(f"\nCrib-free columns: {crib_free}")
    print(f"Count: {len(crib_free)} columns")

    # Show what's on each crib-free column
    print(f"\nCrib-free column contents:")
    for col in crib_free:
        positions = [p for p in range(CT_LEN) if k4_pos_to_grid(p)[1] == col]
        chars = [(p, CT[p]) for p in positions]
        w_marker = " ← has W!" if any(CT[p] == 'W' for p in positions) else ""
        print(f"  Col {col:2d}: {chars}{w_marker}")

    # Generate all 2^9 column masks
    n_free = len(crib_free)
    total_masks = 2 ** n_free
    print(f"\nTotal column masks to test: {total_masks}")

    keywords = load_keywords()
    print(f"Keywords: {len(keywords)}")
    print(f"Cipher variants: {len(CIPHERS) * len(ALPHABETS)}")
    total_tests = total_masks * len(keywords) * len(CIPHERS) * len(ALPHABETS)
    print(f"Total decryptions: {total_tests:,}")
    print()
    sys.stdout.flush()

    # Test all column masks
    REPORT_THRESHOLD = 8
    all_results = []
    masks_tested = 0

    # Group by null count for organized output
    for n_null_cols in range(n_free + 1):
        n_nulls = n_null_cols * 3  # each column contributes 3 nulls (rows 25-27)
        # Adjust: check if row 24 positions fall on any null column
        n_masks = len(list(itertools.combinations(crib_free, n_null_cols)))

        print(f"--- {n_null_cols} null columns → {n_nulls} null positions "
              f"→ {CT_LEN - n_nulls} real chars ({n_masks} masks) ---")
        sys.stdout.flush()

        best_for_count = None

        for null_cols in itertools.combinations(crib_free, n_null_cols):
            null_positions = columns_to_null_positions(null_cols)
            actual_nulls = len(null_positions)
            reduced_len = CT_LEN - actual_nulls
            masks_tested += 1

            best_mapped = 0
            best_result = None

            for keyword in keywords:
                for cipher_name in CIPHERS:
                    for alph_name in ALPHABETS:
                        mapped, free, pt, rlen = decrypt_and_score(
                            null_positions, keyword, cipher_name, alph_name
                        )

                        score = max(mapped, free)
                        if score > best_mapped:
                            best_mapped = score
                            best_result = {
                                "null_cols": null_cols,
                                "null_positions": null_positions,
                                "n_nulls": actual_nulls,
                                "reduced_len": rlen,
                                "keyword": keyword,
                                "cipher": cipher_name,
                                "alphabet": alph_name,
                                "mapped_score": mapped,
                                "free_score": free,
                                "plaintext": pt,
                            }

                        if score >= REPORT_THRESHOLD:
                            all_results.append({
                                "null_cols": null_cols,
                                "null_positions": null_positions,
                                "n_nulls": actual_nulls,
                                "reduced_len": rlen,
                                "keyword": keyword,
                                "cipher": cipher_name,
                                "alphabet": alph_name,
                                "mapped_score": mapped,
                                "free_score": free,
                                "plaintext": pt,
                            })

            if best_result:
                if not best_for_count or best_mapped > best_for_count["mapped_score"]:
                    best_for_count = best_result

        if best_for_count:
            bm = best_for_count["mapped_score"]
            bf = best_for_count["free_score"]
            print(f"  Best: mapped={bm} free={bf} | "
                  f"cols={best_for_count['null_cols']} | "
                  f"{best_for_count['keyword']}/{best_for_count['cipher']}/{best_for_count['alphabet']}")
            if bm >= REPORT_THRESHOLD or bf >= 11:
                print(f"  *** HIT *** PT: {best_for_count['plaintext'][:70]}...")
        else:
            print(f"  (no valid decryptions)")
        sys.stdout.flush()

    elapsed = time.time() - t0

    # ── Final results ────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Masks tested: {masks_tested}")
    print(f"Total decryptions: {total_tests:,}")

    reportable = [r for r in all_results if r["mapped_score"] >= REPORT_THRESHOLD or r["free_score"] >= 11]
    print(f"Results above threshold: {len(reportable)}")

    if reportable:
        reportable.sort(key=lambda r: -max(r["mapped_score"], r["free_score"]))
        print(f"\nTop results:")
        for i, r in enumerate(reportable[:50]):
            print(f"  #{i+1}: mapped={r['mapped_score']} free={r['free_score']} | "
                  f"nulls={r['n_nulls']} cols={r['null_cols']} | "
                  f"{r['keyword']}/{r['cipher']}/{r['alphabet']}")
            print(f"       PT: {r['plaintext'][:70]}...")
    else:
        print("  (none)")

    best_score = max((max(r["mapped_score"], r["free_score"]) for r in all_results), default=0) if all_results else 0
    print(f"\n{'=' * 78}")
    if best_score >= 18:
        print(f"*** SIGNAL (best={best_score}) — investigate ***")
    elif best_score >= REPORT_THRESHOLD:
        print(f"Above noise (best={best_score}) but likely noise at these periods")
    else:
        print(f"NOISE — Column-based null masks: no signal (best={best_score})")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
