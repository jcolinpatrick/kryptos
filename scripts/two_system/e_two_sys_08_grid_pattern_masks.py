#!/usr/bin/env python3
# Cipher:     Two-system Model A (2D grid pattern null masks)
# Family:     two_system
# Status:     active
# Keyspace:   ~50K masks × 704 keywords × 6 variants
# Last run:
# Best score:
#
# E-TWO-SYS-08: Grid-based null mask patterns on the 28×31 Kryptos grid.
#
# Tests geometric null patterns that are constructible on the physical
# copperplate grid. Patterns must respect crib positions (never null a crib).
#
# Pattern families:
#   1. Diagonal: (row + col) % d == r, (row - col) % d == r
#   2. Checkerboard: (row + col) % 2 == r, (row * col) % d == r
#   3. Row+col modular: row % dr == rr AND/OR col % dc == rc
#   4. Manhattan distance from grid points
#   5. Quadrant-based: different rules per quadrant of K4 area
#   6. Spiral/ring distance from center of K4 area
#   7. Column-based with row exceptions (partial columns)
#   8. Every-Nth position in linear scan with grid-aware offsets
#   9. Knight's move patterns from corners/centers
#  10. Bit-based: position where bit k of row or col is set
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)

# ── Grid mapping ─────────────────────────────────────────────────────────

GRID_WIDTH = 31
K4_START_LINEAR = 24 * GRID_WIDTH + 27  # row 24, col 27

def k4_pos_to_grid(p):
    linear = K4_START_LINEAR + p
    return linear // GRID_WIDTH, linear % GRID_WIDTH

# Pre-compute grid coords for all K4 positions
K4_GRID = [k4_pos_to_grid(p) for p in range(CT_LEN)]

# Non-crib positions (candidates for nulls)
NON_CRIB = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)

# ── Ciphers & alphabets ─────────────────────────────────────────────────

def vig_dec(c, k): return (c - k) % MOD
def beau_dec(c, k): return (k - c) % MOD
def vbeau_dec(c, k): return (c + k) % MOD

CIPHERS = {"Vig": vig_dec, "Beau": beau_dec, "VBeau": vbeau_dec}

ALPHABETS = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"
CRIB_LIST = sorted(CRIB_DICT.items())


# ── Pattern generators ───────────────────────────────────────────────────

def generate_all_masks():
    """Generate all geometric null masks. Returns list of (name, null_positions)."""
    masks = {}

    # ── 1. Diagonal patterns: (row + col) % d == r ──
    for d in range(2, 20):
        for r in range(d):
            nulls = [p for p in NON_CRIB
                     if (K4_GRID[p][0] + K4_GRID[p][1]) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"diag_sum_{d}_{r}"] = nulls

    # ── 2. Anti-diagonal: (row - col) % d == r ──
    for d in range(2, 20):
        for r in range(d):
            nulls = [p for p in NON_CRIB
                     if (K4_GRID[p][0] - K4_GRID[p][1]) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"diag_diff_{d}_{r}"] = nulls

    # ── 3. Checkerboard: (row + col) % 2 ──
    for parity in [0, 1]:
        nulls = [p for p in NON_CRIB
                 if (K4_GRID[p][0] + K4_GRID[p][1]) % 2 == parity]
        if 10 <= len(nulls) <= 40:
            masks[f"checker_{parity}"] = nulls

    # ── 4. Row mod × col mod combinations ──
    for dr in range(2, 8):
        for dc in range(2, 8):
            for rr in range(dr):
                for rc in range(dc):
                    # null if row%dr==rr AND col%dc==rc
                    nulls = [p for p in NON_CRIB
                             if K4_GRID[p][0] % dr == rr and K4_GRID[p][1] % dc == rc]
                    if 10 <= len(nulls) <= 40:
                        masks[f"rowcol_and_{dr}_{rr}_{dc}_{rc}"] = nulls

                    # null if row%dr==rr OR col%dc==rc
                    nulls = [p for p in NON_CRIB
                             if K4_GRID[p][0] % dr == rr or K4_GRID[p][1] % dc == rc]
                    if 10 <= len(nulls) <= 40:
                        masks[f"rowcol_or_{dr}_{rr}_{dc}_{rc}"] = nulls

    # ── 5. Product modular: (row * col) % d == r ──
    for d in range(2, 20):
        for r in range(d):
            nulls = [p for p in NON_CRIB
                     if (K4_GRID[p][0] * K4_GRID[p][1]) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"prod_{d}_{r}"] = nulls

    # ── 6. Manhattan distance from K4 center ──
    # K4 center: roughly row 26, col 14 (middle of the K4 area)
    center_row, center_col = 26, 14
    for d_mod in range(2, 12):
        for r in range(d_mod):
            nulls = [p for p in NON_CRIB
                     if (abs(K4_GRID[p][0] - center_row) +
                         abs(K4_GRID[p][1] - center_col)) % d_mod == r]
            if 10 <= len(nulls) <= 40:
                masks[f"manhattan_{d_mod}_{r}"] = nulls

    # ── 7. Chebyshev distance from center ──
    for d_mod in range(2, 12):
        for r in range(d_mod):
            nulls = [p for p in NON_CRIB
                     if max(abs(K4_GRID[p][0] - center_row),
                            abs(K4_GRID[p][1] - center_col)) % d_mod == r]
            if 10 <= len(nulls) <= 40:
                masks[f"chebyshev_{d_mod}_{r}"] = nulls

    # ── 8. Column-based with row parity exceptions ──
    crib_free_cols = [8, 9, 10, 11, 12, 13, 14, 15, 16]
    for n_cols in range(1, 10):
        from itertools import combinations
        for cols in combinations(crib_free_cols, n_cols):
            col_set = set(cols)
            for row_parity in [0, 1]:
                # Only null in these columns on even/odd rows
                nulls = [p for p in NON_CRIB
                         if K4_GRID[p][1] in col_set and
                         K4_GRID[p][0] % 2 == row_parity]
                if 10 <= len(nulls) <= 40:
                    name = f"col_{''.join(str(c) for c in cols)}_rowpar{row_parity}"
                    masks[name] = nulls

    # ── 9. Linear position modular (but on non-crib) ──
    for d in range(3, 15):
        for r in range(d):
            nulls = [p for p in NON_CRIB if p % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"linear_{d}_{r}"] = nulls

    # ── 10. XOR-based: row XOR col ──
    for d in range(2, 16):
        for r in range(d):
            nulls = [p for p in NON_CRIB
                     if (K4_GRID[p][0] ^ K4_GRID[p][1]) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"xor_{d}_{r}"] = nulls

    # ── 11. Weighted: a*row + b*col ──
    for a in range(1, 6):
        for b in range(1, 6):
            if a == 1 and b == 1:
                continue  # already covered by diagonal
            for d in range(2, 12):
                for r in range(d):
                    nulls = [p for p in NON_CRIB
                             if (a * K4_GRID[p][0] + b * K4_GRID[p][1]) % d == r]
                    if 10 <= len(nulls) <= 40:
                        masks[f"weighted_{a}_{b}_{d}_{r}"] = nulls

    # ── 12. Quadratic: row^2 + col^2 ──
    for d in range(2, 16):
        for r in range(d):
            nulls = [p for p in NON_CRIB
                     if (K4_GRID[p][0]**2 + K4_GRID[p][1]**2) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"quad_{d}_{r}"] = nulls

    # ── 13. W-anchored: always include W positions that are non-crib ──
    w_positions = [p for p in range(CT_LEN) if CT[p] == 'W' and p not in CRIB_POSITIONS]
    # W's as seed + extend with each pattern family
    for d in range(2, 15):
        for r in range(d):
            extra = [p for p in NON_CRIB
                     if p not in w_positions and p % d == r]
            nulls = sorted(set(w_positions + extra))
            if 10 <= len(nulls) <= 40:
                masks[f"w_plus_linear_{d}_{r}"] = nulls

    # ── 14. Grid-relative: distance from ENE start / BC end ──
    ene_row, ene_col = K4_GRID[21]  # ENE start
    bc_row, bc_col = K4_GRID[73]    # BC end
    for d in range(2, 12):
        for r in range(d):
            # Distance from ENE start
            nulls = [p for p in NON_CRIB
                     if (abs(K4_GRID[p][0] - ene_row) +
                         abs(K4_GRID[p][1] - ene_col)) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"dist_ene_{d}_{r}"] = nulls

            # Distance from BC end
            nulls = [p for p in NON_CRIB
                     if (abs(K4_GRID[p][0] - bc_row) +
                         abs(K4_GRID[p][1] - bc_col)) % d == r]
            if 10 <= len(nulls) <= 40:
                masks[f"dist_bc_{d}_{r}"] = nulls

    # ── 15. Bit patterns ──
    for bit in range(5):
        # null if bit k of col is set
        nulls = [p for p in NON_CRIB if (K4_GRID[p][1] >> bit) & 1]
        if 10 <= len(nulls) <= 40:
            masks[f"colbit_{bit}"] = nulls

        # null if bit k of col is NOT set
        nulls = [p for p in NON_CRIB if not ((K4_GRID[p][1] >> bit) & 1)]
        if 10 <= len(nulls) <= 40:
            masks[f"colbit_not_{bit}"] = nulls

    # ── 16. Fibonacci/prime positions ──
    fibs = set()
    a, b = 1, 1
    while a < CT_LEN:
        fibs.add(a)
        a, b = b, a + b
    nulls = [p for p in NON_CRIB if p in fibs]
    if 10 <= len(nulls) <= 40:
        masks["fibonacci"] = nulls

    primes = set()
    for n in range(2, CT_LEN):
        if all(n % i != 0 for i in range(2, int(n**0.5) + 1)):
            primes.add(n)
    nulls = [p for p in NON_CRIB if p in primes]
    if 10 <= len(nulls) <= 40:
        masks["primes"] = nulls
    nulls = [p for p in NON_CRIB if p not in primes]
    if 10 <= len(nulls) <= 40:
        masks["composites"] = nulls

    return masks


# ── Scoring ──────────────────────────────────────────────────────────────

def test_mask(null_positions, keywords, report_threshold):
    """Test a mask against all keywords × ciphers × alphabets.

    Returns list of results above threshold, plus best overall.
    """
    null_set = set(null_positions)
    results = []
    best_mapped = 0
    best_result = None

    # Build reduced CT and mapping once
    orig_to_reduced = {}
    reduced_ct_chars = []
    ridx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            reduced_ct_chars.append(CT[i])
            orig_to_reduced[i] = ridx
            ridx += 1
    reduced_len = len(reduced_ct_chars)

    for alph_name, (alph_str, c2i) in ALPHABETS.items():
        # Pre-convert reduced CT to indices
        ct_indices = [c2i[ch] for ch in reduced_ct_chars]

        for cipher_name, dec_fn in CIPHERS.items():
            for keyword in keywords:
                try:
                    kw_indices = [c2i[c] for c in keyword]
                except KeyError:
                    continue
                kw_len = len(kw_indices)

                # Mapped crib score (fast)
                mapped = 0
                for orig_pos, expected in CRIB_LIST:
                    if orig_pos in orig_to_reduced:
                        rpos = orig_to_reduced[orig_pos]
                        c_idx = ct_indices[rpos]
                        k_idx = kw_indices[rpos % kw_len]
                        p_idx = dec_fn(c_idx, k_idx)
                        if alph_str[p_idx] == expected:
                            mapped += 1

                if mapped > best_mapped:
                    best_mapped = mapped
                    # Decrypt full PT for best result
                    pt = "".join(alph_str[dec_fn(ct_indices[i], kw_indices[i % kw_len])]
                                 for i in range(reduced_len))
                    free = 0
                    if CRIB_ENE in pt:
                        free += 13
                    if CRIB_BC in pt:
                        free += 11
                    best_result = {
                        "keyword": keyword,
                        "cipher": cipher_name,
                        "alphabet": alph_name,
                        "mapped_score": mapped,
                        "free_score": free,
                        "plaintext": pt,
                        "reduced_len": reduced_len,
                    }

                if mapped >= report_threshold:
                    pt = "".join(alph_str[dec_fn(ct_indices[i], kw_indices[i % kw_len])]
                                 for i in range(reduced_len))
                    free = 0
                    if CRIB_ENE in pt:
                        free += 13
                    if CRIB_BC in pt:
                        free += 11
                    results.append({
                        "keyword": keyword,
                        "cipher": cipher_name,
                        "alphabet": alph_name,
                        "mapped_score": mapped,
                        "free_score": free,
                        "plaintext": pt,
                        "reduced_len": reduced_len,
                    })

    return results, best_result


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
    for w in ["KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
              "SHADOW", "CIPHER", "SECRET", "BERLIN", "CLOCK",
              "PALIMPSEST", "COMPASS", "LODESTONE", "ENIGMA", "SANBORN", "SCHEIDT"]:
        words.add(w)
    return sorted(words)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 78)
    print("E-TWO-SYS-08: 2D grid pattern null masks")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")

    keywords = load_keywords()
    print(f"Keywords: {len(keywords)}")

    print(f"\nGenerating geometric masks...")
    sys.stdout.flush()
    masks = generate_all_masks()

    # Count by null count
    null_count_dist = {}
    for name, nulls in masks.items():
        n = len(nulls)
        null_count_dist[n] = null_count_dist.get(n, 0) + 1

    print(f"Total unique masks: {len(masks)}")
    print(f"Null count distribution:")
    for n in sorted(null_count_dist):
        print(f"  {n} nulls: {null_count_dist[n]} masks → {CT_LEN - n} real chars")

    total_tests = len(masks) * len(keywords) * len(CIPHERS) * len(ALPHABETS)
    print(f"\nTotal decryptions: {total_tests:,}")
    print()
    sys.stdout.flush()

    REPORT_THRESHOLD = 8
    all_results = []
    tested = 0
    best_overall_score = 0
    best_overall = None

    REPORT_EVERY = 500

    for name, null_positions in sorted(masks.items()):
        hits, best = test_mask(null_positions, keywords, REPORT_THRESHOLD)
        tested += 1

        if hits:
            all_results.extend([(name, null_positions, r) for r in hits])
            for r in hits:
                print(f"  *** HIT: {name} ({len(null_positions)} nulls) | "
                      f"{r['keyword']}/{r['cipher']}/{r['alphabet']} "
                      f"mapped={r['mapped_score']} free={r['free_score']}")
                sys.stdout.flush()

        if best and best["mapped_score"] > best_overall_score:
            best_overall_score = best["mapped_score"]
            best_overall = (name, null_positions, best)

        if tested % REPORT_EVERY == 0:
            elapsed = time.time() - t0
            print(f"  [{tested}/{len(masks)} masks] {elapsed:.1f}s | "
                  f"best_mapped={best_overall_score} | hits={len(all_results)}")
            sys.stdout.flush()

    elapsed = time.time() - t0

    # ── Results ──────────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"Masks tested: {tested}")
    print(f"Total decryptions: {total_tests:,}")

    if best_overall:
        name, nulls, r = best_overall
        print(f"\nBest overall: mapped={r['mapped_score']} free={r['free_score']}")
        print(f"  Pattern: {name}")
        print(f"  Nulls ({len(nulls)}): {nulls}")
        print(f"  {r['keyword']}/{r['cipher']}/{r['alphabet']}")
        print(f"  PT: {r['plaintext'][:70]}...")

    reportable = [(n, np, r) for n, np, r in all_results
                  if r["mapped_score"] >= REPORT_THRESHOLD or r["free_score"] >= 11]

    print(f"\nResults above threshold: {len(reportable)}")
    if reportable:
        reportable.sort(key=lambda x: -max(x[2]["mapped_score"], x[2]["free_score"]))
        for i, (name, nulls, r) in enumerate(reportable[:50]):
            print(f"  #{i+1}: mapped={r['mapped_score']} free={r['free_score']} | "
                  f"{name} ({len(nulls)} nulls) | "
                  f"{r['keyword']}/{r['cipher']}/{r['alphabet']}")
            print(f"       PT: {r['plaintext'][:70]}...")
    else:
        print("  (none)")

    print(f"\n{'=' * 78}")
    if best_overall_score >= 18:
        print(f"*** SIGNAL (best={best_overall_score}) — investigate ***")
    elif best_overall_score >= REPORT_THRESHOLD:
        print(f"Above noise (best={best_overall_score})")
    else:
        print(f"NOISE — 2D grid pattern null masks: no signal (best={best_overall_score})")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
