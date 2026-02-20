#!/usr/bin/env python3
"""
E-S-47: Period-7 Vigenère After Transposition — Constraint Enumeration

MOTIVATION: E-S-45 showed the lag-7 autocorrelation (z=3.036) is best explained
by a period-7 key (P(≥9)=12.5% vs 0.7% for random key). Period-7 Vigenère is
eliminated under DIRECT correspondence, but NOT after transposition.

MODEL:
  intermediate[i] = CT[σ(i)]    (transposition layer)
  PT[i] = intermediate[i] - key[i%7] mod 26  (period-7 Vigenère)

  Equivalently: CT[σ(p)] = (PT[p] + key[p%7]) mod 26

For crib position p with known PT[p], this constrains σ(p):
  σ(p) must be a CT position where CT[σ(p)] = (PT[p] + key[p%7]) mod 26

APPROACH:
  For each residue r (0-6):
    - List crib positions at residue r: {p : p in cribs, p%7 == r}
    - For each key[r] value (0-25):
      - Compute required CT letter for each crib position
      - Find all CT positions with that letter
      - Count valid injective assignments (σ(p) distinct for all p in residue r)

  Then multiply across residues to get total (key, partial-σ) combinations.
  If ZERO valid combinations → period-7 Vig + transposition ELIMINATED.
  If manageable count → enumerate and test with quadgram scoring.

Output: results/e_s_47_period7_transposition.json
"""

import json
import sys
import os
import time
from collections import defaultdict, Counter
from itertools import product as itertools_product
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX

N = CT_LEN


def get_ct_positions_by_letter():
    """Map each letter to list of CT positions where it appears."""
    pos_by_letter = defaultdict(list)
    for i, c in enumerate(CT):
        pos_by_letter[c].append(i)
    return pos_by_letter


def get_residue_crib_groups(period):
    """Group crib positions by residue class mod period."""
    groups = defaultdict(list)
    for pos, pt_char in sorted(CRIB_DICT.items()):
        groups[pos % period].append((pos, pt_char))
    return groups


def count_valid_assignments(required_letters, ct_positions_by_letter, used_positions=None):
    """Count valid injective assignments: each required letter maps to a distinct CT position.

    required_letters: list of (crib_pos, required_ct_letter)
    Returns: (count_of_valid_assignments, list_of_options_per_position)
    """
    if used_positions is None:
        used_positions = set()

    options = []
    for crib_pos, req_letter in required_letters:
        available = [p for p in ct_positions_by_letter[req_letter] if p not in used_positions]
        options.append((crib_pos, req_letter, available))

    if not options:
        return 1, []

    # Count injective assignments using inclusion-exclusion or direct enumeration
    # For small groups (≤6 positions), direct enumeration is fine
    n_positions = len(options)

    if n_positions <= 8:
        return enumerate_injective(options)
    else:
        # Upper bound: product of available counts
        upper = 1
        for _, _, avail in options:
            upper *= len(avail)
        return upper, options


def enumerate_injective(options):
    """Directly enumerate valid injective assignments for small groups."""
    count = 0
    assignments = []

    def backtrack(idx, used):
        nonlocal count
        if idx == len(options):
            count += 1
            if count <= 10:
                assignments.append(dict(used))
            return
        crib_pos, req_letter, available = options[idx]
        for ct_pos in available:
            if ct_pos not in used:
                used[crib_pos] = ct_pos
                backtrack(idx + 1, used)
                del used[crib_pos]

    backtrack(0, {})
    return count, assignments


def analyze_period7_model():
    """Main analysis: enumerate valid (key, partial-σ) for period-7 + transposition."""
    print("=" * 70)
    print("E-S-47: Period-7 Vigenère After Transposition")
    print("=" * 70)

    ct_by_letter = get_ct_positions_by_letter()

    print(f"\nCT letter frequencies:")
    freq = Counter(CT)
    for letter in sorted(freq.keys()):
        print(f"  {letter}: {freq[letter]}", end="")
    print()

    residue_groups = get_residue_crib_groups(7)
    print(f"\nCrib positions by residue class mod 7:")
    for r in range(7):
        positions = residue_groups.get(r, [])
        print(f"  r={r}: {[(p, c) for p, c in positions]} ({len(positions)} positions)")

    # For each residue class and each key value, compute valid assignments
    print(f"\n--- Per-Residue Analysis ---")

    residue_results = {}
    for r in range(7):
        crib_positions = residue_groups.get(r, [])
        if not crib_positions:
            print(f"  Residue {r}: no crib positions → key[{r}] unconstrained (26 values)")
            residue_results[r] = {
                'n_crib_positions': 0,
                'valid_keys': list(range(26)),
                'n_valid_keys': 26,
                'total_assignments': 26,
                'details': {},
            }
            continue

        print(f"\n  Residue {r}: {len(crib_positions)} crib positions")
        valid_keys = []
        key_details = {}

        for key_val in range(26):
            # For each crib position p at this residue, compute required CT letter
            required = []
            for pos, pt_char in crib_positions:
                req_ct_idx = (ALPH_IDX[pt_char] + key_val) % 26
                req_ct_letter = ALPH[req_ct_idx]
                required.append((pos, req_ct_letter))

            # Check if valid injective assignment exists
            n_valid, sample_assignments = count_valid_assignments(required, ct_by_letter)

            if n_valid > 0:
                valid_keys.append(key_val)
                key_details[key_val] = {
                    'n_assignments': n_valid,
                    'required_letters': [(p, l) for p, l in required],
                    'sample': sample_assignments[:3] if isinstance(sample_assignments, list) else [],
                }

                print(f"    key[{r}]={key_val:2d} ({ALPH[key_val]}): "
                      f"{n_valid:,} valid σ assignments "
                      f"(requires: {', '.join(f'CT[σ({p})]={l}' for p, l in required)})")

        print(f"    → {len(valid_keys)}/26 key values feasible")

        residue_results[r] = {
            'n_crib_positions': len(crib_positions),
            'valid_keys': valid_keys,
            'n_valid_keys': len(valid_keys),
            'total_assignments': sum(key_details[k]['n_assignments'] for k in valid_keys),
            'details': key_details,
        }

    # Compute total combinations
    print(f"\n--- Cross-Residue Combination Count ---")
    total_key_combos = 1
    for r in range(7):
        n = residue_results[r]['n_valid_keys']
        total_key_combos *= n
        print(f"  Residue {r}: {n} valid key values")

    print(f"\n  Total key combinations: {total_key_combos:,}")

    if total_key_combos == 0:
        print(f"\n  *** VERDICT: ELIMINATED — no valid key exists ***")
        return residue_results, 0

    # Compute total (key, σ) combinations (upper bound — ignores cross-residue σ conflicts)
    # Actual count requires checking that σ values are globally distinct
    total_sigma_upper = 1
    for r in range(7):
        res = residue_results[r]
        if res['n_crib_positions'] > 0:
            max_assignments = max(res['details'][k]['n_assignments'] for k in res['valid_keys'])
            total_sigma_upper *= max_assignments

    print(f"  Upper bound on (key, σ) pairs: ~{total_key_combos} × {total_sigma_upper:,}")

    return residue_results, total_key_combos


def cross_residue_enumeration(residue_results):
    """Enumerate valid key combinations across all residues, checking σ consistency."""
    print(f"\n--- Cross-Residue Enumeration ---")

    ct_by_letter = get_ct_positions_by_letter()
    residue_groups = get_residue_crib_groups(7)

    # Build list of valid key values per residue
    valid_keys_per_residue = []
    for r in range(7):
        valid_keys_per_residue.append(residue_results[r]['valid_keys'])

    total_combos = 1
    for vk in valid_keys_per_residue:
        total_combos *= len(vk)

    print(f"  Total key combinations to check: {total_combos:,}")

    if total_combos > 1_000_000:
        print(f"  Too many to enumerate exhaustively. Sampling...")
        return sample_cross_residue(residue_results, residue_groups, ct_by_letter, n_samples=100000)

    valid_full_keys = []
    checked = 0

    for key_combo in itertools_product(*valid_keys_per_residue):
        checked += 1
        if checked % 10000 == 0:
            print(f"    [{checked:,}/{total_combos:,}] {len(valid_full_keys)} valid so far")

        # Build required CT letter for each crib position
        required_all = []
        for r in range(7):
            for pos, pt_char in residue_groups.get(r, []):
                req_ct_idx = (ALPH_IDX[pt_char] + key_combo[r]) % 26
                req_ct_letter = ALPH[req_ct_idx]
                required_all.append((pos, req_ct_letter))

        # Check if valid injective assignment exists across ALL residues simultaneously
        n_valid, samples = count_valid_assignments(required_all, ct_by_letter)

        if n_valid > 0:
            key_str = ''.join(ALPH[k] for k in key_combo)
            valid_full_keys.append({
                'key': key_combo,
                'key_str': key_str,
                'n_sigma_assignments': n_valid,
                'sample_sigma': samples[:3] if isinstance(samples, list) else [],
            })
            if len(valid_full_keys) <= 20:
                print(f"    VALID: key={key_str} → {n_valid:,} σ assignments")

    print(f"\n  Checked: {checked:,} key combinations")
    print(f"  Valid: {len(valid_full_keys)}")

    return valid_full_keys


def sample_cross_residue(residue_results, residue_groups, ct_by_letter, n_samples):
    """Sample random key combinations and check σ consistency."""
    import random
    random.seed(42)

    valid_keys_per_residue = [residue_results[r]['valid_keys'] for r in range(7)]

    valid_count = 0
    total_sigma = 0

    for trial in range(n_samples):
        key_combo = tuple(random.choice(vk) for vk in valid_keys_per_residue)

        required_all = []
        for r in range(7):
            for pos, pt_char in residue_groups.get(r, []):
                req_ct_idx = (ALPH_IDX[pt_char] + key_combo[r]) % 26
                req_ct_letter = ALPH[req_ct_idx]
                required_all.append((pos, req_ct_letter))

        n_valid, _ = count_valid_assignments(required_all, ct_by_letter)
        if n_valid > 0:
            valid_count += 1
            total_sigma += n_valid

        if (trial + 1) % 10000 == 0:
            print(f"    [{trial+1:,}/{n_samples:,}] {valid_count} valid ({valid_count/(trial+1)*100:.1f}%)")

    total_combos = 1
    for vk in valid_keys_per_residue:
        total_combos *= len(vk)

    est_valid = int(valid_count / n_samples * total_combos)
    est_sigma = int(total_sigma / max(valid_count, 1) * est_valid)

    print(f"\n  Sampled: {n_samples:,}")
    print(f"  Valid keys: {valid_count}/{n_samples} ({valid_count/n_samples*100:.1f}%)")
    print(f"  Estimated total valid keys: ~{est_valid:,} / {total_combos:,}")
    print(f"  Average σ per valid key: ~{total_sigma/max(valid_count,1):.0f}")
    print(f"  Estimated total (key, σ) pairs: ~{est_sigma:,}")

    return {
        'mode': 'sampled',
        'n_samples': n_samples,
        'valid_count': valid_count,
        'valid_fraction': round(valid_count / n_samples, 4),
        'estimated_valid_keys': est_valid,
        'total_key_space': total_combos,
        'avg_sigma_per_key': round(total_sigma / max(valid_count, 1), 1),
        'estimated_total_pairs': est_sigma,
    }


def test_beaufort_model():
    """Same analysis but for Beaufort: CT[σ(p)] = (key[p%7] - PT[p]) mod 26"""
    print(f"\n--- Beaufort Variant ---")

    ct_by_letter = get_ct_positions_by_letter()
    residue_groups = get_residue_crib_groups(7)

    residue_results = {}
    for r in range(7):
        crib_positions = residue_groups.get(r, [])
        if not crib_positions:
            residue_results[r] = {'n_valid_keys': 26, 'valid_keys': list(range(26))}
            continue

        valid_keys = []
        for key_val in range(26):
            required = []
            for pos, pt_char in crib_positions:
                req_ct_idx = (key_val - ALPH_IDX[pt_char]) % 26
                req_ct_letter = ALPH[req_ct_idx]
                required.append((pos, req_ct_letter))

            n_valid, _ = count_valid_assignments(required, ct_by_letter)
            if n_valid > 0:
                valid_keys.append(key_val)

        print(f"  Residue {r}: {len(valid_keys)}/26 Beaufort key values feasible")
        residue_results[r] = {'n_valid_keys': len(valid_keys), 'valid_keys': valid_keys}

    total = 1
    for r in range(7):
        total *= residue_results[r]['n_valid_keys']
    print(f"  Total Beaufort key combinations: {total:,}")

    return residue_results, total


def test_variant_beaufort_model():
    """Variant Beaufort: CT[σ(p)] = (PT[p] - key[p%7]) mod 26"""
    print(f"\n--- Variant Beaufort ---")

    ct_by_letter = get_ct_positions_by_letter()
    residue_groups = get_residue_crib_groups(7)

    residue_results = {}
    for r in range(7):
        crib_positions = residue_groups.get(r, [])
        if not crib_positions:
            residue_results[r] = {'n_valid_keys': 26, 'valid_keys': list(range(26))}
            continue

        valid_keys = []
        for key_val in range(26):
            required = []
            for pos, pt_char in crib_positions:
                req_ct_idx = (ALPH_IDX[pt_char] - key_val) % 26
                req_ct_letter = ALPH[req_ct_idx]
                required.append((pos, req_ct_letter))

            n_valid, _ = count_valid_assignments(required, ct_by_letter)
            if n_valid > 0:
                valid_keys.append(key_val)

        print(f"  Residue {r}: {len(valid_keys)}/26 VB key values feasible")
        residue_results[r] = {'n_valid_keys': len(valid_keys), 'valid_keys': valid_keys}

    total = 1
    for r in range(7):
        total *= residue_results[r]['n_valid_keys']
    print(f"  Total VB key combinations: {total:,}")

    return residue_results, total


def main():
    t0 = time.time()

    # Vigenère model
    vig_results, vig_combos = analyze_period7_model()

    # Cross-residue enumeration (if feasible)
    if vig_combos > 0:
        cross_results = cross_residue_enumeration(vig_results)
    else:
        cross_results = None

    # Beaufort model
    beau_results, beau_combos = test_beaufort_model()

    # Variant Beaufort
    vb_results, vb_combos = test_variant_beaufort_model()

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Vigenère key combos: {vig_combos:,}")
    print(f"  Beaufort key combos: {beau_combos:,}")
    print(f"  Variant Beaufort combos: {vb_combos:,}")
    total_all = vig_combos + beau_combos + vb_combos
    print(f"  Total across variants: {total_all:,}")

    if total_all == 0:
        verdict = "ELIMINATED — no valid period-7 key + transposition exists"
    else:
        verdict = f"VIABLE — {total_all:,} key combinations, need σ enumeration"

    print(f"  Verdict: {verdict}")
    print(f"  Time: {elapsed:.1f}s")

    results = {
        'experiment': 'E-S-47',
        'model': 'period-7 substitution after arbitrary transposition',
        'vigenere': {
            'valid_key_combos': vig_combos,
            'per_residue': {str(r): {
                'n_valid_keys': vig_results[r]['n_valid_keys'],
                'valid_keys': vig_results[r]['valid_keys'],
            } for r in range(7)},
        },
        'beaufort': {
            'valid_key_combos': beau_combos,
        },
        'variant_beaufort': {
            'valid_key_combos': vb_combos,
        },
        'cross_residue': cross_results if isinstance(cross_results, dict) else
            {'n_valid': len(cross_results) if cross_results else 0},
        'verdict': verdict,
        'elapsed_seconds': round(elapsed, 1),
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_47_period7_transposition.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"  Artifact: results/e_s_47_period7_transposition.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_47_period7_after_transposition.py")


if __name__ == "__main__":
    main()
