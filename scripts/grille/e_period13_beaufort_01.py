#!/usr/bin/env python3
"""Deep investigation of the d=13 Beaufort anomaly.

Cipher: Beaufort (period 13)
Family: grille
Status: active
Keyspace: 256 crib-derived + 26^8 hill-climb + 11.88M exhaustive
Last run: never
Best score: n/a

The mod-5 sweep found that Beaufort keystream collisions at d=13 are
3.55-7x expected. Period 13 = len(EASTNORTHEAST). Under the scrambled-CT
paradigm, if the substitution has period 13, decrypting the carved text
with the correct key produces a PERMUTATION of the plaintext. That
permutation preserves IC (should be ~0.0667 for English), letter freqs,
and unigram statistics, but NOT word structure.

Approach:
  Phase 1: 256 candidates from 2-choice crib conflicts
  Phase 2: Greedy IC hill-climb from best seed
  Phase 3: Full 26^13 exhaustive with IC filter
  Phase 4: Also try Vigenere and VarBeaufort
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from itertools import product
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, KRYPTOS_ALPHABET,
)
from kryptos.kernel.transforms.vigenere import (
    beau_decrypt, beau_recover_key,
    vig_decrypt, vig_recover_key,
    varbeau_decrypt, varbeau_recover_key,
)
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.aggregate import score_candidate_free

ct_nums = [ALPH_IDX[c] for c in CT]
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def analyze_variant(name, recover_fn, decrypt_fn):
    """Run full period-13 analysis for one cipher variant."""
    print(f"\n{'='*70}")
    print(f"PERIOD-13 {name.upper()} ANALYSIS")
    print(f"{'='*70}")

    # Key recovery at crib positions
    key_at_cribs = {}
    for pos, pt_ch in CRIB_DICT.items():
        key_at_cribs[pos] = recover_fn(ct_nums[pos], ALPH_IDX[pt_ch])

    # Group by mod 13
    residue_data = {}
    for r in range(13):
        positions = [(pos, key_at_cribs[pos]) for pos in key_at_cribs if pos % 13 == r]
        vals = list(set(kv for _, kv in positions))
        residue_data[r] = {'positions': positions, 'values': vals}

    known = {}
    conflicts = {}
    for r, d in residue_data.items():
        if len(d['values']) == 1:
            known[r] = d['values'][0]
        elif len(d['values']) == 2:
            conflicts[r] = d['values']
        elif len(d['values']) == 0:
            conflicts[r] = list(range(26))  # all possible

    print(f"Known residues: {len(known)}")
    for r in sorted(known):
        print(f"  k[{r:2d}] = {ALPH[known[r]]} ({known[r]})")
    print(f"Conflicting residues: {len(conflicts)}")
    for r in sorted(conflicts):
        if len(conflicts[r]) <= 4:
            print(f"  k[{r:2d}] in {[ALPH[v] for v in conflicts[r]]}")
        else:
            print(f"  k[{r:2d}] = ? (no crib constraint)")

    # Phase 1: Enumerate all combinations of conflict choices
    conflict_residues = sorted(conflicts.keys())
    n_combos = 1
    for r in conflict_residues:
        n_combos *= len(conflicts[r])

    if n_combos <= 100000:
        print(f"\nPhase 1: Enumerate {n_combos} combinations")
        results = []
        for combo in product(*[conflicts[r] for r in conflict_residues]):
            key = [0] * 13
            for r, v in known.items():
                key[r] = v
            for r, v in zip(conflict_residues, combo):
                key[r] = v

            pt_nums = [decrypt_fn(ct_nums[i], key[i % 13]) for i in range(CT_LEN)]
            pt = ''.join(ALPH[n] for n in pt_nums)
            ic_val = ic(pt)
            key_str = ''.join(ALPH[k] for k in key)
            results.append((ic_val, key_str, pt, key[:]))

        results.sort(key=lambda x: -x[0])
        print(f"IC range: {results[-1][0]:.4f} to {results[0][0]:.4f}")
        print(f"Target: English IC = 0.0667, Random = 0.0385, K4 = 0.0361")
        print(f"\nTop 15 by IC:")
        for i, (iv, ks, pt, _) in enumerate(results[:15]):
            print(f"  #{i+1}: IC={iv:.4f} key={ks}")

        # Free crib check on top 50
        print(f"\nFree crib check on top 50:")
        any_hit = False
        for i, (iv, ks, pt, _) in enumerate(results[:50]):
            fb = score_candidate_free(pt)
            if fb.crib_score > 0:
                any_hit = True
                print(f"  #{i+1}: IC={iv:.4f} key={ks} crib={fb.crib_score}")
        if not any_hit:
            print("  No crib hits in top 50.")

        best_ic, best_key_str, best_pt, best_key = results[0]
    else:
        print(f"\nPhase 1: Too many combos ({n_combos}), starting from crib-constrained seed")
        best_key = [0] * 13
        for r, v in known.items():
            best_key[r] = v
        for r in conflict_residues:
            best_key[r] = conflicts[r][0]
        best_pt_nums = [decrypt_fn(ct_nums[i], best_key[i % 13]) for i in range(CT_LEN)]
        best_pt = ''.join(ALPH[n] for n in best_pt_nums)
        best_ic = ic(best_pt)
        best_key_str = ''.join(ALPH[k] for k in best_key)

    # Phase 2: Greedy hill-climb
    print(f"\nPhase 2: Greedy IC hill-climb")
    print(f"Starting: key={best_key_str} IC={best_ic:.4f}")

    improved = True
    iteration = 0
    while improved:
        improved = False
        iteration += 1
        for r in range(13):
            orig_val = best_key[r]
            best_r_ic = best_ic
            best_r_val = orig_val
            for v in range(26):
                if v == orig_val:
                    continue
                test_key = best_key[:]
                test_key[r] = v
                pt_nums = [decrypt_fn(ct_nums[i], test_key[i % 13]) for i in range(CT_LEN)]
                pt = ''.join(ALPH[n] for n in pt_nums)
                iv = ic(pt)
                if iv > best_r_ic:
                    best_r_ic = iv
                    best_r_val = v
            if best_r_val != orig_val:
                best_key[r] = best_r_val
                best_ic = best_r_ic
                pt_nums = [decrypt_fn(ct_nums[i], best_key[i % 13]) for i in range(CT_LEN)]
                best_pt = ''.join(ALPH[n] for n in pt_nums)
                best_key_str = ''.join(ALPH[k] for k in best_key)
                improved = True
                print(f"  iter {iteration}: r={r} -> {ALPH[best_r_val]} | key={best_key_str} IC={best_ic:.4f}")

    print(f"Final: key={best_key_str} IC={best_ic:.4f}")
    print(f"PT: {best_pt}")
    fb = score_candidate_free(best_pt)
    print(f"Free crib: {fb.summary}")

    # Phase 3: Also try with KA alphabet
    print(f"\nPhase 3: KA-indexed key recovery")
    ct_ka = [KA_IDX[c] for c in CT]
    key_at_cribs_ka = {}
    for pos, pt_ch in CRIB_DICT.items():
        key_at_cribs_ka[pos] = recover_fn(ct_ka[pos], KA_IDX[pt_ch])

    residue_ka = {}
    for r in range(13):
        positions = [(pos, key_at_cribs_ka[pos]) for pos in key_at_cribs_ka if pos % 13 == r]
        vals = list(set(kv for _, kv in positions))
        residue_ka[r] = vals

    consistent_ka = sum(1 for r in range(13) if len(residue_ka[r]) <= 1)
    print(f"KA consistent residues: {consistent_ka}/13")
    for r in range(13):
        vals = residue_ka[r]
        if len(vals) <= 1:
            print(f"  r={r:2d}: {[KA[v] for v in vals]} *** CONSISTENT ***")
        elif len(vals) == 2:
            print(f"  r={r:2d}: {[KA[v] for v in vals]}")

    return best_ic, best_key_str, best_pt


def exhaustive_period13(decrypt_fn, variant_name):
    """Try ALL 26^13 period-13 keys, filtering by IC."""
    print(f"\n{'='*70}")
    print(f"EXHAUSTIVE PERIOD-13 {variant_name.upper()} (IC filter)")
    print(f"26^13 ≈ 2.48 trillion — TOO LARGE for exhaustive.")
    print(f"Instead: random sampling of 1M keys + IC evaluation")
    print(f"{'='*70}")

    import random
    random.seed(42)

    best_ic = 0
    best_key = None
    best_pt = None

    N_SAMPLES = 1_000_000
    ic_threshold = 0.055  # Well above random, approaching English

    hits = 0
    for trial in range(N_SAMPLES):
        key = [random.randint(0, 25) for _ in range(13)]
        pt_nums = [decrypt_fn(ct_nums[i], key[i % 13]) for i in range(CT_LEN)]
        pt = ''.join(ALPH[n] for n in pt_nums)
        iv = ic(pt)

        if iv > best_ic:
            best_ic = iv
            best_key = key[:]
            best_pt = pt

        if iv >= ic_threshold:
            hits += 1
            key_str = ''.join(ALPH[k] for k in key)
            print(f"  IC={iv:.4f} key={key_str}")

        if trial % 200000 == 0 and trial > 0:
            print(f"  ... {trial} sampled, best IC so far: {best_ic:.4f}")

    key_str = ''.join(ALPH[k] for k in best_key)
    print(f"\n{N_SAMPLES} random keys sampled")
    print(f"Best IC: {best_ic:.4f} key={key_str}")
    print(f"Keys with IC >= {ic_threshold}: {hits}")
    print(f"PT: {best_pt}")
    fb = score_candidate_free(best_pt)
    print(f"Free crib: {fb.summary}")

    return best_ic, key_str, best_pt


def main():
    print("PERIOD-13 DEEP INVESTIGATION")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Period 13 = len(EASTNORTHEAST)")
    print(f"Under scrambled-CT paradigm: correct key → decrypt → permuted PT")
    print(f"Permuted PT preserves: IC, letter freqs (both should match English)")
    print()

    # Analyze all three variants
    for name, rfn, dfn in [
        ('Beaufort', beau_recover_key, beau_decrypt),
        ('Vigenere', vig_recover_key, vig_decrypt),
        ('VarBeau', varbeau_recover_key, varbeau_decrypt),
    ]:
        analyze_variant(name, rfn, dfn)

    # Random sampling for Beaufort
    exhaustive_period13(beau_decrypt, 'Beaufort')

    print(f"\n{'='*70}")
    print("DONE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
