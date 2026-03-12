#!/usr/bin/env python3
"""MITM: Transposition × Substitution on 73-char column mask extract.

Model: PT → transposition → substitution → CT₇₃ → insert 24 nulls → CT₉₇
Digram test proved outermost layer = substitution.

For each columnar transposition σ and period p:
  - Map crib PT positions through σ to get intermediate positions
  - Check if CT at those intermediate positions is consistent with periodic sub
  - If consistent, derive the key and report

GENUINELY DIFFERENT from the raw-97 product cipher campaign because:
  1. CT is 73 chars (24 nulls removed)
  2. Crib positions are shifted (13-25, 47-57)
  3. Transposition operates on 73 chars, not 97

Cipher: columnar_trans × periodic_sub
Family: grille
Status: active
Keyspace: ~20M configs
Last run: never
Best score: N/A
"""
import sys
import os
import itertools
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, MOD, CRIB_WORDS


def extract_73(ct97: str, keep_col: int) -> str:
    """Extract 73 chars by removing 8 of 9 columns from band 8-16."""
    row25_band = set(range(12, 21))
    row26_band = set(range(43, 52))
    row27_band = set(range(74, 83))
    keep_pos = {4 + keep_col, 35 + keep_col, 66 + keep_col}
    nulls = (row25_band | row26_band | row27_band) - keep_pos
    return ''.join(ct97[i] for i in range(len(ct97)) if i not in nulls)


def get_crib_pairs_73() -> list[tuple[int, int]]:
    """Crib pairs as (position_in_73, plaintext_value)."""
    pairs = []
    for orig_start, word in CRIB_WORDS:
        shift = 8 if orig_start == 21 else 16
        for i, ch in enumerate(word):
            pairs.append((orig_start + i - shift, ord(ch) - 65))
    return pairs


def columnar_perm(n: int, w: int, col_order: tuple) -> list[int]:
    """Compute the columnar transposition permutation.

    Write plaintext into grid of width w (row by row), read out
    in column order. Returns perm where output[i] = input[perm[i]].

    perm[output_pos] = input_pos (gather convention).
    """
    rows = (n + w - 1) // w
    # Number of columns with 'rows' entries
    full_cols = n - (rows - 1) * w if n % w != 0 else w

    perm = []
    for col in col_order:
        col_len = rows if col < full_cols else rows - 1
        for row in range(col_len):
            input_pos = row * w + col
            if input_pos < n:
                perm.append(input_pos)
    return perm


def invert_perm(perm: list[int]) -> list[int]:
    """Invert a permutation. inv[perm[i]] = i."""
    n = len(perm)
    inv = [0] * n
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_consistency(ct73: str, crib_pairs: list[tuple[int, int]],
                       sigma: list[int], period: int,
                       variant: str) -> tuple[int, list[int] | None]:
    """Check if transposition σ + periodic sub with given period is consistent.

    Model: PT[j] → intermediate[σ(j)] → CT[σ(j)] via substitution
    Or equivalently: CT[i] = sub(PT[σ⁻¹(i)], key[i % p])

    But wait — the key could be applied at PLAINTEXT positions or CT positions.
    Key at CT position i: CT[i] = (intermediate[i] + key[i%p]) mod 26
    intermediate[i] = PT[σ⁻¹(i)]

    Returns (n_matches, derived_key) where n_matches is how many crib
    positions are consistent and derived_key is the partial key (or None).
    """
    sigma_inv = invert_perm(sigma)
    n = len(ct73)

    # For each crib position j (in PT space):
    #   intermediate position = sigma[j]
    #   CT at position sigma[j] = sub(PT[j], key[sigma[j] % period])
    #
    # Derive required key value at each residue class
    residue_keys: dict[int, list[int]] = defaultdict(list)

    for pt_pos, pt_val in crib_pairs:
        if pt_pos >= n:
            continue
        intermediate_pos = sigma[pt_pos]
        ct_val = ord(ct73[intermediate_pos]) - 65
        residue = intermediate_pos % period

        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "var_beaufort":
            k = (pt_val - ct_val) % MOD
        else:
            raise ValueError

        residue_keys[residue].append(k)

    # Check consistency: all key values in same residue must be equal
    matches = 0
    conflicts = 0
    derived_key = [None] * period

    for residue, key_vals in residue_keys.items():
        if len(set(key_vals)) == 1:
            matches += len(key_vals)
            derived_key[residue] = key_vals[0]
        else:
            conflicts += 1
            # Count how many match the most common value
            from collections import Counter
            mc = Counter(key_vals).most_common(1)[0][1]
            matches += mc

    return matches, derived_key if conflicts == 0 else None


def check_consistency_key_at_pt(ct73: str, crib_pairs: list[tuple[int, int]],
                                 sigma: list[int], period: int,
                                 variant: str) -> tuple[int, list[int] | None]:
    """Alternative: key applied at PLAINTEXT position, not intermediate.

    CT[sigma[j]] = sub(PT[j], key[j % period])
    """
    n = len(ct73)
    residue_keys: dict[int, list[int]] = defaultdict(list)

    for pt_pos, pt_val in crib_pairs:
        if pt_pos >= n:
            continue
        intermediate_pos = sigma[pt_pos]
        ct_val = ord(ct73[intermediate_pos]) - 65
        residue = pt_pos % period  # Key at PT position

        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "var_beaufort":
            k = (pt_val - ct_val) % MOD
        else:
            raise ValueError

        residue_keys[residue].append(k)

    matches = 0
    conflicts = 0
    derived_key = [None] * period

    for residue, key_vals in residue_keys.items():
        if len(set(key_vals)) == 1:
            matches += len(key_vals)
            derived_key[residue] = key_vals[0]
        else:
            conflicts += 1
            from collections import Counter
            mc = Counter(key_vals).most_common(1)[0][1]
            matches += mc

    return matches, derived_key if conflicts == 0 else None


def decrypt_full(ct73: str, sigma: list[int], key: list[int],
                 variant: str, key_at_ct: bool = True) -> str:
    """Full decryption: undo sub, then undo trans."""
    n = len(ct73)
    sigma_inv = invert_perm(sigma)

    # Step 1: undo substitution
    intermediate = []
    for i in range(n):
        c = ord(ct73[i]) - 65
        k = key[i % len(key)] if key_at_ct else key[sigma_inv[i] % len(key)]
        if k is None:
            intermediate.append('?')
            continue

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        intermediate.append(chr(p + 65))

    # Step 2: undo transposition (read at sigma_inv positions)
    pt = ['?'] * n
    for j in range(n):
        pt[j] = intermediate[sigma[j]]

    return ''.join(pt)


def main():
    print("=" * 70)
    print("MITM: TRANSPOSITION × SUBSTITUTION ON 73-CHAR COLUMN EXTRACT")
    print("=" * 70)

    # Use keep_col=8 as representative (crib positions same for all)
    ct73 = extract_73(CT, 8)
    crib_pairs = get_crib_pairs_73()
    n = len(ct73)
    assert n == 73

    variants = ["vigenere", "beaufort", "var_beaufort"]
    key_modes = ["ct_pos", "pt_pos"]  # Where the key period is applied

    best_score = 0
    best_configs = []
    total_checked = 0

    # ── Exhaustive columnar for widths 7-9 ──────────────────────────────
    for w in range(7, 10):
        n_perms = 1
        for i in range(1, w + 1):
            n_perms *= i

        print(f"\nWidth {w}: {n_perms:,} column orderings × {13} periods × 3 variants × 2 key modes")

        for col_order in itertools.permutations(range(w)):
            perm = columnar_perm(n, w, col_order)
            if len(perm) != n:
                continue

            for period in range(1, 14):
                for variant in variants:
                    # Mode 1: Key at CT/intermediate position
                    score, key = check_consistency(
                        ct73, crib_pairs, perm, period, variant)
                    total_checked += 1

                    if score > best_score:
                        best_score = score
                        best_configs = []
                    if score >= best_score and score >= 18:
                        best_configs.append(
                            (score, f"w{w}/{variant}/p{period}/key@ct "
                             f"cols={col_order}", key, perm))

                    # Mode 2: Key at PT position
                    score2, key2 = check_consistency_key_at_pt(
                        ct73, crib_pairs, perm, period, variant)
                    total_checked += 1

                    if score2 > best_score:
                        best_score = score2
                        best_configs = []
                    if score2 >= best_score and score2 >= 18:
                        best_configs.append(
                            (score2, f"w{w}/{variant}/p{period}/key@pt "
                             f"cols={col_order}", key2, perm))

        print(f"  Checked {total_checked:,} so far, best: {best_score}/24")

    # ── Rail fence for depths 2-15 ──────────────────────────────────────
    print(f"\nRail fence (depths 2-15):")
    for depth in range(2, 16):
        # Compute rail fence permutation
        rails = [[] for _ in range(depth)]
        rail, direction = 0, 1
        for i in range(n):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == depth - 1:
                direction = -1
            rail += direction

        perm = []
        for rail_list in rails:
            perm.extend(rail_list)

        # perm[output_pos] = input_pos (gather)
        if len(perm) != n:
            continue

        for period in range(1, 14):
            for variant in variants:
                score, key = check_consistency(
                    ct73, crib_pairs, perm, period, variant)
                total_checked += 1
                if score > best_score:
                    best_score = score
                    best_configs = []
                if score >= best_score and score >= 18:
                    best_configs.append(
                        (score, f"railfence_d{depth}/{variant}/p{period}/key@ct",
                         key, perm))

                score2, key2 = check_consistency_key_at_pt(
                    ct73, crib_pairs, perm, period, variant)
                total_checked += 1
                if score2 > best_score:
                    best_score = score2
                    best_configs = []
                if score2 >= best_score and score2 >= 18:
                    best_configs.append(
                        (score2, f"railfence_d{depth}/{variant}/p{period}/key@pt",
                         key2, perm))

    print(f"  Checked {total_checked:,} so far, best: {best_score}/24")

    # ── Route cipher reading orders ─────────────────────────────────────
    print(f"\nRoute cipher (grid reading orders for widths 7-14):")
    for w in [7, 8, 9, 10, 11, 12, 13, 14]:
        rows = (n + w - 1) // w
        full_cols = n % w if n % w != 0 else w

        # Serpentine (boustrophedon)
        perm_serp = []
        for r in range(rows):
            row_indices = []
            for c in range(w):
                idx = r * w + c
                if idx < n:
                    row_indices.append(idx)
            if r % 2 == 1:
                row_indices.reverse()
            perm_serp.extend(row_indices)

        # Spiral (outside-in, clockwise)
        grid = [[None] * w for _ in range(rows)]
        idx = 0
        for r in range(rows):
            for c in range(w):
                if idx < n:
                    grid[r][c] = idx
                    idx += 1

        perm_spiral = []
        top, bottom, left, right = 0, rows - 1, 0, w - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                if top < rows and c < w and grid[top][c] is not None:
                    perm_spiral.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                if r < rows and right < w and grid[r][right] is not None:
                    perm_spiral.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if bottom < rows and c < w and grid[bottom][c] is not None:
                        perm_spiral.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if r < rows and left < w and grid[r][left] is not None:
                        perm_spiral.append(grid[r][left])
                left += 1

        # Column-by-column (top to bottom)
        perm_colwise = []
        for c in range(w):
            for r in range(rows):
                idx = r * w + c
                if idx < n:
                    perm_colwise.append(idx)

        for perm, name in [(perm_serp, f"serpentine_w{w}"),
                           (perm_spiral, f"spiral_w{w}"),
                           (perm_colwise, f"colwise_w{w}")]:
            if len(perm) != n:
                continue
            if len(set(perm)) != n:
                continue

            for period in range(1, 14):
                for variant in variants:
                    score, key = check_consistency(
                        ct73, crib_pairs, perm, period, variant)
                    total_checked += 1
                    if score > best_score:
                        best_score = score
                        best_configs = []
                    if score >= best_score and score >= 18:
                        best_configs.append(
                            (score, f"{name}/{variant}/p{period}/key@ct",
                             key, perm))

                    score2, key2 = check_consistency_key_at_pt(
                        ct73, crib_pairs, perm, period, variant)
                    total_checked += 1
                    if score2 > best_score:
                        best_score = score2
                        best_configs = []
                    if score2 >= best_score and score2 >= 18:
                        best_configs.append(
                            (score2, f"{name}/{variant}/p{period}/key@pt",
                             key2, perm))

    print(f"  Checked {total_checked:,} so far, best: {best_score}/24")

    # ── Final report ─────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"RESULTS: {total_checked:,} total configs")
    print(f"Best score: {best_score}/24")
    print(f"{'='*70}")

    if best_configs:
        for score, desc, key, perm in sorted(best_configs, reverse=True)[:10]:
            print(f"\n  {score}/24  {desc}")
            if key:
                key_str = ''.join(chr(k + 65) if k is not None else '?' for k in key)
                print(f"         Key: {key_str}")
                # Try to decrypt
                is_ct_key = "key@ct" in desc
                pt = decrypt_full(ct73, perm, key, desc.split('/')[1],
                                  key_at_ct=is_ct_key)
                print(f"         PT:  {pt[:50]}...")
    else:
        print("  No configs scored >= 18/24")

    # Show best scores by width for context
    print(f"\n{'='*70}")
    print("BEST SCORES BY CATEGORY (for context):")
    if best_score < 18:
        print(f"  Overall best: {best_score}/24 = ", end="")
        if best_score <= 9:
            print("NOISE (expected random ≈ 8-9 for large periods)")
        elif best_score <= 14:
            print("MARGINAL (could be noise at medium periods)")
        elif best_score <= 17:
            print("ELEVATED (check period for underdetermination)")
        else:
            print("SIGNAL")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
