#!/usr/bin/env python3
"""Verify the 18/24 MITM results and assess statistical significance.

Tests: w9/vigenere/p11/key@ct with the 4 column orderings that scored 18/24.
Also runs a null hypothesis test: how often does a random w9 permutation
score 18+ at period 11?
"""
import sys
import os
import random
import itertools
from collections import defaultdict, Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, MOD, CRIB_WORDS


def extract_73(ct97, keep_col):
    row25_band = set(range(12, 21))
    row26_band = set(range(43, 52))
    row27_band = set(range(74, 83))
    keep_pos = {4 + keep_col, 35 + keep_col, 66 + keep_col}
    nulls = (row25_band | row26_band | row27_band) - keep_pos
    return ''.join(ct97[i] for i in range(len(ct97)) if i not in nulls)


def get_crib_pairs_73():
    pairs = []
    for orig_start, word in CRIB_WORDS:
        shift = 8 if orig_start == 21 else 16
        for i, ch in enumerate(word):
            pairs.append((orig_start + i - shift, ord(ch) - 65))
    return pairs


def columnar_perm(n, w, col_order):
    rows = (n + w - 1) // w
    full_cols = n - (rows - 1) * w if n % w != 0 else w
    perm = []
    for col in col_order:
        col_len = rows if col < full_cols else rows - 1
        for row in range(col_len):
            input_pos = row * w + col
            if input_pos < n:
                perm.append(input_pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def analyze_config(ct73, crib_pairs, col_order, period, variant="vigenere"):
    """Full analysis of a specific config."""
    n = len(ct73)
    perm = columnar_perm(n, len(col_order), col_order)
    sigma_inv = invert_perm(perm)

    # Group crib positions by intermediate residue class
    residue_groups = defaultdict(list)  # residue -> [(pt_pos, pt_val, int_pos, ct_val, key_val)]

    for pt_pos, pt_val in crib_pairs:
        int_pos = perm[pt_pos]  # intermediate position = sigma(pt_pos)
        ct_val = ord(ct73[int_pos]) - 65
        if variant == "vigenere":
            key_val = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            key_val = (ct_val + pt_val) % MOD
        elif variant == "var_beaufort":
            key_val = (pt_val - ct_val) % MOD
        residue = int_pos % period
        residue_groups[residue].append((pt_pos, pt_val, int_pos, ct_val, key_val))

    # Score and derive majority-vote key
    total_matches = 0
    key = [None] * period
    conflicts = []

    for residue in range(period):
        group = residue_groups.get(residue, [])
        if not group:
            continue
        key_vals = [g[4] for g in group]
        counter = Counter(key_vals)
        most_common_val, most_common_count = counter.most_common(1)[0]
        key[residue] = most_common_val
        total_matches += most_common_count
        if len(set(key_vals)) > 1:
            conflicts.append((residue, group))

    return total_matches, key, residue_groups, conflicts


def decrypt_full(ct73, col_order, key, period, variant="vigenere"):
    """Full decryption: undo sub at CT positions, then undo transposition."""
    n = len(ct73)
    perm = columnar_perm(n, len(col_order), col_order)
    sigma_inv = invert_perm(perm)

    # Step 1: undo substitution (at each CT position i, use key[i % period])
    intermediate = []
    for i in range(n):
        c = ord(ct73[i]) - 65
        k = key[i % period] if key[i % period] is not None else 0
        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        intermediate.append(chr(p + 65))

    # Step 2: undo transposition
    # perm[j] = the input position that goes to output position j
    # intermediate[i] = PT[sigma_inv[i]], so PT[j] = intermediate[sigma[j]] = intermediate[perm[j]]
    # Wait, let me think carefully.
    # Encryption: write PT row-by-row into grid, read column-by-column.
    # perm gives the READ ORDER: intermediate[0] = PT[perm[0]], intermediate[1] = PT[perm[1]], ...
    # So intermediate[i] = PT[perm[i]]
    # After sub: CT[i] = sub(intermediate[i]) = sub(PT[perm[i]])
    # Decryption: intermediate[i] = unsub(CT[i]), then PT[perm[i]] = intermediate[i]
    # So PT[j] = intermediate[sigma_inv[j]] where sigma_inv[perm[i]] = i

    pt = ['?'] * n
    for i in range(n):
        pt[perm[i]] = intermediate[i]
    return ''.join(pt)


def ic(text):
    """Index of coincidence."""
    freq = Counter(text)
    n = len(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def main():
    ct73 = extract_73(CT, 8)
    crib_pairs = get_crib_pairs_73()
    n = len(ct73)

    # The 4 column orderings that scored 18/24
    configs = [
        (8, 6, 4, 2, 3, 7, 5, 1, 0),
        (5, 6, 4, 2, 3, 7, 1, 8, 0),
        (3, 6, 4, 2, 8, 7, 5, 1, 0),
        (3, 6, 4, 2, 5, 7, 1, 8, 0),
    ]

    print("=" * 70)
    print("VERIFICATION OF 18/24 MITM RESULTS")
    print("=" * 70)

    for col_order in configs:
        print(f"\n{'─'*70}")
        print(f"Column order: {col_order}")
        print(f"Width 9, Period 11, Vigenère, key at CT position")
        print(f"{'─'*70}")

        score, key, groups, conflicts = analyze_config(
            ct73, crib_pairs, col_order, 11, "vigenere")

        key_str = ''.join(chr(k + 65) if k is not None else '?' for k in key)
        print(f"Score: {score}/24")
        print(f"Key (majority vote): {key_str}")
        print(f"Key values: {key}")

        # Show residue groups
        print(f"\nResidue class breakdown:")
        for r in range(11):
            group = groups.get(r, [])
            if not group:
                continue
            key_vals = [g[4] for g in group]
            consistent = "✓" if len(set(key_vals)) == 1 else "✗"
            entries = ', '.join(
                f"pt{g[0]}({chr(g[1]+65)})→ct{g[2]}({chr(g[3]+65)}) k={g[4]}"
                for g in group)
            print(f"  r={r:2d} [{consistent}] key={key[r]:2d}({chr(key[r]+65)}): {entries}")

        if conflicts:
            print(f"\nConflicts ({len(conflicts)} residue classes):")
            for residue, group in conflicts:
                key_vals = [g[4] for g in group]
                print(f"  r={residue}: keys={key_vals} → majority={Counter(key_vals).most_common(1)[0]}")

        # Decrypt
        pt = decrypt_full(ct73, col_order, key, 11, "vigenere")
        print(f"\nDecrypted text: {pt}")
        print(f"IC: {ic(pt):.4f} (English=0.067, random=0.038)")

        # Check cribs in plaintext
        print(f"\nCrib check in PT:")
        ene_match = sum(1 for i, ch in enumerate("EASTNORTHEAST")
                       if 13 + i < len(pt) and pt[13 + i] == ch)
        bc_match = sum(1 for i, ch in enumerate("BERLINCLOCK")
                      if 47 + i < len(pt) and pt[47 + i] == ch)
        print(f"  ENE at 13-25: {ene_match}/13 matches")
        print(f"  BC  at 47-57: {bc_match}/11 matches")
        print(f"  PT[13:26] = {pt[13:26]}")
        print(f"  PT[47:58] = {pt[47:58]}")

    # ── Statistical significance test ────────────────────────────────────
    print(f"\n{'='*70}")
    print("STATISTICAL SIGNIFICANCE TEST")
    print(f"{'='*70}")
    print("Testing 100,000 random w=9 permutations at period 11...")

    random.seed(42)
    score_counts = Counter()
    max_random = 0
    n_trials = 100_000

    for trial in range(n_trials):
        # Random column order
        col_order = list(range(9))
        random.shuffle(col_order)
        col_order = tuple(col_order)

        perm = columnar_perm(n, 9, col_order)
        if len(perm) != n:
            continue

        # Compute score at period 11
        residue_keys = defaultdict(list)
        for pt_pos, pt_val in crib_pairs:
            int_pos = perm[pt_pos]
            ct_val = ord(ct73[int_pos]) - 65
            k = (ct_val - pt_val) % MOD
            residue_keys[int_pos % 11].append(k)

        score = 0
        for key_vals in residue_keys.values():
            score += Counter(key_vals).most_common(1)[0][1]

        score_counts[score] += 1
        if score > max_random:
            max_random = score

    print(f"Random trials: {n_trials:,}")
    print(f"Max random score: {max_random}/24")
    print(f"\nScore distribution:")
    for s in sorted(score_counts.keys()):
        pct = 100 * score_counts[s] / n_trials
        bar = '#' * max(1, int(pct))
        print(f"  {s:2d}/24: {score_counts[s]:6d} ({pct:5.2f}%) {bar}")

    n_ge_18 = sum(score_counts[s] for s in score_counts if s >= 18)
    print(f"\nP(score ≥ 18) = {n_ge_18}/{n_trials} = {n_ge_18/n_trials:.6f}")

    # For the FULL search space (362,880 w=9 permutations):
    p_per_trial = n_ge_18 / n_trials if n_ge_18 > 0 else 1 / n_trials
    expected_hits = 362880 * p_per_trial
    print(f"Expected ≥18 hits in full w=9 search (362,880 perms): {expected_hits:.1f}")

    print(f"\n{'='*70}")
    if expected_hits > 10:
        print("VERDICT: 18/24 at p=11, w=9 is NOISE (expected by chance).")
    elif expected_hits > 1:
        print("VERDICT: 18/24 at p=11, w=9 is MARGINAL (could be chance).")
    elif expected_hits < 0.01:
        print("VERDICT: 18/24 at p=11, w=9 is SIGNIFICANT. Investigate!")
    else:
        print("VERDICT: 18/24 at p=11, w=9 is UNLIKELY by chance. Investigate!")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
