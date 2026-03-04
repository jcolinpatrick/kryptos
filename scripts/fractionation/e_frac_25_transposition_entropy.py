#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-25: Transposition Effect on Apparent Key Entropy

E-FRAC-16 found the apparent Beaufort key at crib positions has entropy at
the 0.3rd percentile of random (p=0.003). E-FRAC-24 showed this key text
is incompatible with natural language. The question: does transposition
explain this low entropy?

If K4 = Transposition(Substitution(PT)):
- The "apparent key" we compute (assuming no transposition) is NOT the true key
- apparent_key[j] = true_key[j] + (PT[j] - PT[σ⁻¹(j)]) mod 26

This experiment tests: for random transposition σ and random periodic key,
how often is the apparent key entropy at or below the observed value?

If the answer is "often" (>5%), transposition explains the low entropy.
If "rarely" (<1%), transposition alone doesn't explain it.
"""

import json
import math
import random
import time
from collections import Counter
from pathlib import Path

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)


def shannon_entropy(values):
    """Compute Shannon entropy of a list of integer values."""
    counts = Counter(values)
    n = len(values)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def main():
    start_time = time.time()
    random.seed(42)
    results = {}

    print("=" * 70)
    print("E-FRAC-25: Transposition Effect on Apparent Key Entropy")
    print("=" * 70)

    # Known key values
    beau_vals = list(BEAUFORT_KEY_ENE) + list(BEAUFORT_KEY_BC)
    vig_vals = list(VIGENERE_KEY_ENE) + list(VIGENERE_KEY_BC)
    crib_positions = sorted(CRIB_DICT.keys())
    n_cribs = len(crib_positions)

    # Observed entropies
    beau_entropy = shannon_entropy(beau_vals)
    vig_entropy = shannon_entropy(vig_vals)
    print(f"\nObserved entropies:")
    print(f"  Beaufort: {beau_entropy:.4f} bits")
    print(f"  Vigenère: {vig_entropy:.4f} bits")
    print(f"  Maximum (uniform): {math.log2(26):.4f} bits")

    # Pre-compute PT values at crib positions
    crib_pt = {}
    for pos, ch in CRIB_DICT.items():
        crib_pt[pos] = ALPH_IDX[ch]

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 1: Null model — random key, no transposition
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 1: Null Model — Random Key, No Transposition")
    print("=" * 60)

    N_MC = 500_000
    null_entropies = []
    for _ in range(N_MC):
        vals = [random.randint(0, 25) for _ in range(n_cribs)]
        null_entropies.append(shannon_entropy(vals))

    beau_null_pctile = sum(1 for e in null_entropies if e <= beau_entropy) / N_MC
    vig_null_pctile = sum(1 for e in null_entropies if e <= vig_entropy) / N_MC

    print(f"  Beaufort entropy {beau_entropy:.4f}: {beau_null_pctile*100:.2f}th percentile")
    print(f"  Vigenère entropy {vig_entropy:.4f}: {vig_null_pctile*100:.2f}th percentile")

    results['part1_null'] = {
        'beau_entropy': beau_entropy,
        'beau_null_pctile': beau_null_pctile,
        'vig_entropy': vig_entropy,
        'vig_null_pctile': vig_null_pctile,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 2: Transposition model — random σ + periodic key
    # apparent_key[j] = (true_key[j] + PT[j] - PT[σ⁻¹(j)]) mod 26
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 2: Transposition Model — Random σ + Periodic Key")
    print("=" * 60)

    # Need to handle the fact that σ⁻¹(j) might not be a crib position,
    # so we don't know PT[σ⁻¹(j)]. In this case, we model PT at unknown
    # positions as random characters.

    N_MC_TRANS = 200_000

    trans_entropies_beau = []
    trans_entropies_vig = []

    for _ in range(N_MC_TRANS):
        # Random permutation
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        perm_inv = [0] * CT_LEN
        for i in range(CT_LEN):
            perm_inv[perm[i]] = i

        # Random periodic key (period 5-7)
        period = random.choice([5, 6, 7])
        base_key = [random.randint(0, 25) for _ in range(period)]

        # Compute apparent key at crib positions
        apparent_beau = []
        apparent_vig = []
        for pos in crib_positions:
            true_key_val = base_key[pos % period]

            # PT at position σ⁻¹(pos):
            sigma_inv_pos = perm_inv[pos]
            if sigma_inv_pos in crib_pt:
                pt_sigma = crib_pt[sigma_inv_pos]
            else:
                pt_sigma = random.randint(0, 25)  # Unknown PT → random

            pt_j = crib_pt[pos]

            # Beaufort: apparent = true_key + PT[j] - PT[σ⁻¹(j)] mod 26
            app_beau = (true_key_val + pt_j - pt_sigma) % 26
            # Vigenère: apparent = true_key - PT[σ⁻¹(j)] + PT[j] mod 26
            # (same formula for Beaufort and Vigenère apparent keys
            #  because the displacement PT[j]-PT[σ⁻¹(j)] is the same)
            apparent_beau.append(app_beau)
            apparent_vig.append(app_beau)  # Same distribution

        trans_entropies_beau.append(shannon_entropy(apparent_beau))

    beau_trans_pctile = sum(1 for e in trans_entropies_beau
                           if e <= beau_entropy) / N_MC_TRANS

    print(f"\n  Under random σ + periodic key (periods 5-7):")
    print(f"  Apparent key entropy distribution:")
    trans_mean = sum(trans_entropies_beau) / len(trans_entropies_beau)
    trans_std = (sum((e - trans_mean)**2 for e in trans_entropies_beau) / len(trans_entropies_beau)) ** 0.5
    print(f"    Mean: {trans_mean:.4f}, Std: {trans_std:.4f}")
    print(f"    Min: {min(trans_entropies_beau):.4f}, Max: {max(trans_entropies_beau):.4f}")
    print(f"  Observed Beaufort entropy ({beau_entropy:.4f}): {beau_trans_pctile*100:.2f}th percentile")

    # Compare with null model
    print(f"\n  Comparison:")
    print(f"    Null model (no transposition):  {beau_null_pctile*100:.2f}th percentile")
    print(f"    Transposition model:            {beau_trans_pctile*100:.2f}th percentile")
    if beau_trans_pctile > beau_null_pctile:
        print(f"    → Transposition makes low entropy MORE likely (by {beau_trans_pctile/max(beau_null_pctile, 0.001):.1f}x)")
    else:
        print(f"    → Transposition makes low entropy LESS likely")

    results['part2_transposition'] = {
        'beau_trans_pctile': beau_trans_pctile,
        'trans_mean': trans_mean,
        'trans_std': trans_std,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 3: Structured transposition models
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 3: Structured Transposition Models")
    print("=" * 60)

    def columnar_perm(width, col_order, n=CT_LEN):
        """Generate a columnar transposition permutation."""
        rows = (n + width - 1) // width
        perm = []
        for col in col_order:
            for row in range(rows):
                pos = row * width + col
                if pos < n:
                    perm.append(pos)
        return perm

    struct_results = {}

    for width in [7, 9, 11]:
        entropies = []
        n_samples = min(50000, math.factorial(width))

        for trial in range(n_samples):
            # Random column ordering
            col_order = list(range(width))
            random.shuffle(col_order)
            perm = columnar_perm(width, col_order)

            perm_inv = [0] * CT_LEN
            for i in range(CT_LEN):
                perm_inv[perm[i]] = i

            # Random periodic key
            period = random.choice([5, 6, 7])
            base_key = [random.randint(0, 25) for _ in range(period)]

            apparent = []
            for pos in crib_positions:
                true_key_val = base_key[pos % period]
                sigma_inv_pos = perm_inv[pos]
                pt_sigma = crib_pt.get(sigma_inv_pos, random.randint(0, 25))
                pt_j = crib_pt[pos]
                apparent.append((true_key_val + pt_j - pt_sigma) % 26)

            entropies.append(shannon_entropy(apparent))

        pctile = sum(1 for e in entropies if e <= beau_entropy) / len(entropies)
        mean_e = sum(entropies) / len(entropies)

        print(f"\n  Width-{width} columnar + periodic key:")
        print(f"    Mean apparent entropy: {mean_e:.4f}")
        print(f"    P(entropy ≤ {beau_entropy:.4f}): {pctile*100:.2f}%")

        struct_results[f'w{width}'] = {'mean': mean_e, 'pctile': pctile}

    results['part3_structured'] = struct_results

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 4: What if some crib positions are NOT transposed?
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 4: Partial Transposition — Some Positions Fixed")
    print("=" * 60)

    # If the transposition leaves some crib positions in place (σ(j)=j),
    # then at those positions apparent_key = true_key (no displacement).
    # The entropy of the apparent key would be a mix of true key values
    # and displaced key values.

    for n_fixed in [4, 8, 12, 16, 20]:
        entropies = []
        for _ in range(100_000):
            perm = list(range(CT_LEN))
            random.shuffle(perm)
            perm_inv = [0] * CT_LEN
            for i in range(CT_LEN):
                perm_inv[perm[i]] = i

            period = random.choice([5, 6, 7])
            base_key = [random.randint(0, 25) for _ in range(period)]

            # Fix n_fixed random crib positions
            fixed_positions = set(random.sample(crib_positions, min(n_fixed, n_cribs)))

            apparent = []
            for pos in crib_positions:
                true_key_val = base_key[pos % period]
                if pos in fixed_positions:
                    # No transposition at this position
                    apparent.append(true_key_val)
                else:
                    sigma_inv_pos = perm_inv[pos]
                    pt_sigma = crib_pt.get(sigma_inv_pos, random.randint(0, 25))
                    pt_j = crib_pt[pos]
                    apparent.append((true_key_val + pt_j - pt_sigma) % 26)

            entropies.append(shannon_entropy(apparent))

        pctile = sum(1 for e in entropies if e <= beau_entropy) / len(entropies)
        mean_e = sum(entropies) / len(entropies)
        print(f"  {n_fixed}/{n_cribs} crib positions fixed: mean_entropy={mean_e:.4f}, "
              f"P(≤{beau_entropy:.4f})={pctile*100:.2f}%")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Part 5: Running key model (non-periodic)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 60)
    print("Part 5: Running Key + Transposition")
    print("=" * 60)

    # If the true key is a running key (random text), each key value is
    # independently drawn from some language distribution.
    # Under transposition, apparent_key has same distribution as the
    # null model (both independent uniform-ish)

    N_RK = 200_000
    rk_entropies = []
    for _ in range(N_RK):
        # Random running key (English-weighted)
        eng_weights = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202,
                       0.0609, 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675,
                       0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276,
                       0.0098, 0.0236, 0.0015, 0.0197, 0.0007]
        key_97 = random.choices(range(26), weights=eng_weights, k=CT_LEN)

        perm = list(range(CT_LEN))
        random.shuffle(perm)
        perm_inv = [0] * CT_LEN
        for i in range(CT_LEN):
            perm_inv[perm[i]] = i

        apparent = []
        for pos in crib_positions:
            true_key_val = key_97[pos]
            sigma_inv_pos = perm_inv[pos]
            pt_sigma = crib_pt.get(sigma_inv_pos, random.randint(0, 25))
            pt_j = crib_pt[pos]
            apparent.append((true_key_val + pt_j - pt_sigma) % 26)

        rk_entropies.append(shannon_entropy(apparent))

    rk_pctile = sum(1 for e in rk_entropies if e <= beau_entropy) / N_RK
    rk_mean = sum(rk_entropies) / len(rk_entropies)

    print(f"  Running key (English) + random transposition:")
    print(f"    Mean apparent entropy: {rk_mean:.4f}")
    print(f"    P(≤{beau_entropy:.4f}): {rk_pctile*100:.2f}%")

    # Running key without transposition
    rk_no_trans_entropies = []
    for _ in range(N_RK):
        key_97 = random.choices(range(26), weights=eng_weights, k=CT_LEN)
        apparent = [key_97[pos] for pos in crib_positions]
        rk_no_trans_entropies.append(shannon_entropy(apparent))

    rk_no_trans_pctile = sum(1 for e in rk_no_trans_entropies
                            if e <= beau_entropy) / N_RK
    rk_no_trans_mean = sum(rk_no_trans_entropies) / len(rk_no_trans_entropies)

    print(f"\n  Running key (English) WITHOUT transposition:")
    print(f"    Mean apparent entropy: {rk_no_trans_mean:.4f}")
    print(f"    P(≤{beau_entropy:.4f}): {rk_no_trans_pctile*100:.2f}%")

    results['part5_running_key'] = {
        'rk_trans_pctile': rk_pctile,
        'rk_trans_mean': rk_mean,
        'rk_no_trans_pctile': rk_no_trans_pctile,
        'rk_no_trans_mean': rk_no_trans_mean,
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    runtime = time.time() - start_time

    print("\n" + "=" * 70)
    print("SUMMARY: E-FRAC-25 — Transposition Effect on Key Entropy")
    print("=" * 70)

    print(f"\n  Observed Beaufort key entropy: {beau_entropy:.4f} bits")
    print(f"\n  Model comparison (lower percentile = more unusual):")
    print(f"    Null (uniform random key):            {beau_null_pctile*100:.2f}th percentile")
    print(f"    Random σ + periodic key (p=5-7):      {beau_trans_pctile*100:.2f}th percentile")
    for w, data in struct_results.items():
        print(f"    Columnar {w} + periodic key:           {data['pctile']*100:.2f}th percentile")
    print(f"    Running key (English) + random σ:     {rk_pctile*100:.2f}th percentile")
    print(f"    Running key (English) no transposition: {rk_no_trans_pctile*100:.2f}th percentile")

    # Determine which model best explains the low entropy
    models = [
        ('Null', beau_null_pctile),
        ('Random σ + periodic', beau_trans_pctile),
        ('Running key + σ', rk_pctile),
        ('Running key, no σ', rk_no_trans_pctile),
    ]
    for w, data in struct_results.items():
        models.append((f'Columnar {w} + periodic', data['pctile']))

    models.sort(key=lambda x: -x[1])  # Higher percentile = less unusual = better fit

    print(f"\n  Best fitting model (highest percentile = least unusual):")
    for name, p in models:
        marker = " ← BEST" if p == models[0][1] else ""
        print(f"    {name:40s}: {p*100:.2f}%{marker}")

    all_under_1pct = all(p < 0.01 for _, p in models)
    any_above_5pct = any(p >= 0.05 for _, p in models)

    if all_under_1pct:
        print(f"\n  VERDICT: LOW_ENTROPY_UNEXPLAINED — no tested model explains the")
        print(f"  Beaufort key's low entropy. P < 1% under ALL models.")
        print(f"  The low entropy is a genuine anomaly that requires explanation.")
        verdict = 'LOW_ENTROPY_UNEXPLAINED'
    elif any_above_5pct:
        best_name = models[0][0]
        best_p = models[0][1]
        print(f"\n  VERDICT: EXPLAINED_BY_{best_name.upper().replace(' ','_')} — ")
        print(f"  P = {best_p*100:.1f}% under this model (> 5%), within normal range")
        verdict = f'EXPLAINED_BY_{best_name}'
    else:
        print(f"\n  VERDICT: MARGINALLY_UNUSUAL — low entropy is unusual (1-5%)")
        print(f"  under all models, but not dramatically so.")
        verdict = 'MARGINALLY_UNUSUAL'

    print(f"\nRuntime: {runtime:.1f}s")
    print(f"RESULT: verdict={verdict}")

    results['summary'] = {
        'verdict': verdict,
        'model_percentiles': {name: p for name, p in models},
        'runtime': runtime,
    }

    # Save
    out_dir = Path("results/frac")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "e_frac_25_transposition_entropy.json"
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
