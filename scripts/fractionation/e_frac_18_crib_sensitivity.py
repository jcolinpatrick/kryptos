#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-18: Crib Position Sensitivity Analysis

Meta-risk test: Are any crib positions off by ±1 or ±2?

The persistent 14-17/24 scoring ceiling across ALL cipher families has been
interpreted as evidence for a transposition layer. But an alternative explanation:
if any crib positions are wrong, the true ceiling would be <24/24 for the correct
cipher, and every sweep would show a cap.

The bimodal fingerprint (positions 21-33 match well, 63-73 don't) could reflect
which cribs are correct rather than which positions are transposed.

Tests:
1. Block shifts: move entire ENE (13 chars) and/or BC (11 chars) by ±1, ±2
2. Individual position shifts: for each of 24 crib positions, shift it ±1
3. For each shifted crib set, test periodic Vig/Beaufort consistency (periods 2-15)
4. Compare shifted scores vs. original scores

Key question: Does shifting any crib subset DRAMATICALLY improve the best score?
"""

import json
import os
import time
from itertools import product
from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT, CRIB_WORDS,
    N_CRIBS, BEAN_EQ, BEAN_INEQ,
)


def derive_key(ct_pos: int, pt_char: str, variant: str) -> int:
    """Derive key value at a position given CT and PT characters."""
    ct_val = ALPH_IDX[CT[ct_pos]]
    pt_val = ALPH_IDX[pt_char]
    if variant == 'vigenere':
        return (ct_val - pt_val) % MOD
    elif variant == 'beaufort':
        return (ct_val + pt_val) % MOD
    elif variant == 'variant_beaufort':
        return (pt_val - ct_val) % MOD
    else:
        raise ValueError(f"Unknown variant: {variant}")


def build_crib_dict(ene_offset: int = 0, bc_offset: int = 0,
                     individual_shifts: dict = None) -> dict:
    """Build a crib dictionary with optional shifts.

    Args:
        ene_offset: shift entire ENE block by this many positions
        bc_offset: shift entire BC block by this many positions
        individual_shifts: {original_pos: new_pos} for individual position shifts
    """
    cribs = {}
    # ENE: "EASTNORTHEAST" starting at position 21
    ene_start = 21 + ene_offset
    for i, ch in enumerate("EASTNORTHEAST"):
        pos = ene_start + i
        if 0 <= pos < CT_LEN:
            cribs[pos] = ch

    # BC: "BERLINCLOCK" starting at position 63
    bc_start = 63 + bc_offset
    for i, ch in enumerate("BERLINCLOCK"):
        pos = bc_start + i
        if 0 <= pos < CT_LEN:
            cribs[pos] = ch

    # Apply individual shifts
    if individual_shifts:
        new_cribs = {}
        for orig_pos, new_pos in individual_shifts.items():
            if orig_pos in cribs and 0 <= new_pos < CT_LEN:
                new_cribs[new_pos] = cribs[orig_pos]
                del cribs[orig_pos]
        cribs.update(new_cribs)

    return cribs


def check_periodic_consistency(crib_dict: dict, variant: str, period: int) -> int:
    """Check how many crib positions are consistent with a periodic key.

    For each residue class (mod period), all key values must be identical.
    Count max matches using majority voting per residue.
    """
    if not crib_dict:
        return 0

    # Group key values by residue class
    residue_keys = {}
    for pos, pt_char in crib_dict.items():
        if 0 <= pos < CT_LEN:
            k = derive_key(pos, pt_char, variant)
            r = pos % period
            if r not in residue_keys:
                residue_keys[r] = []
            residue_keys[r].append(k)

    # For each residue, count the most common key value
    total_matches = 0
    for r, keys in residue_keys.items():
        if keys:
            counts = Counter(keys)
            total_matches += counts.most_common(1)[0][1]

    return total_matches


def check_bean_constraints(crib_dict: dict, variant: str) -> tuple:
    """Check Bean equality and inequality constraints for a crib dict.

    Returns (eq_pass, ineq_pass_count, ineq_total)
    """
    # Bean equality: k[27] = k[65]
    eq_pass = True
    for eq_a, eq_b in BEAN_EQ:
        if eq_a in crib_dict and eq_b in crib_dict:
            ka = derive_key(eq_a, crib_dict[eq_a], variant)
            kb = derive_key(eq_b, crib_dict[eq_b], variant)
            if ka != kb:
                eq_pass = False

    # Bean inequalities
    ineq_pass = 0
    ineq_total = 0
    for ineq_a, ineq_b in BEAN_INEQ:
        if ineq_a in crib_dict and ineq_b in crib_dict:
            ka = derive_key(ineq_a, crib_dict[ineq_a], variant)
            kb = derive_key(ineq_b, crib_dict[ineq_b], variant)
            ineq_total += 1
            if ka != kb:
                ineq_pass += 1

    return eq_pass, ineq_pass, ineq_total


def best_periodic_score(crib_dict: dict, periods: range = range(2, 16)) -> dict:
    """Find the best periodic score across all variants and periods."""
    best = {'score': 0, 'variant': '', 'period': 0, 'n_cribs': len(crib_dict)}

    for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
        for period in periods:
            score = check_periodic_consistency(crib_dict, variant, period)
            if score > best['score']:
                best = {
                    'score': score,
                    'variant': variant,
                    'period': period,
                    'n_cribs': len(crib_dict),
                }
    return best


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-18: Crib Position Sensitivity Analysis")
    print("=" * 70)

    results = {}

    # ── Baseline: original cribs ──────────────────────────────────────────
    print("\n--- Baseline (original crib positions) ---")
    baseline_cribs = dict(CRIB_DICT)
    baseline_best = best_periodic_score(baseline_cribs)
    print(f"  Original best: {baseline_best['score']}/{len(baseline_cribs)} "
          f"(variant={baseline_best['variant']}, period={baseline_best['period']})")
    results['baseline'] = baseline_best

    # Check Bean constraints for baseline
    for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
        eq_pass, ineq_pass, ineq_total = check_bean_constraints(baseline_cribs, variant)
        print(f"  Bean ({variant}): eq={'PASS' if eq_pass else 'FAIL'}, "
              f"ineq={ineq_pass}/{ineq_total}")

    # ── Test 1: Block shifts ─────────────────────────────────────────────
    print("\n--- Test 1: Block shifts (ENE and/or BC shifted ±1, ±2) ---")
    block_results = []

    for ene_off in [-2, -1, 0, 1, 2]:
        for bc_off in [-2, -1, 0, 1, 2]:
            if ene_off == 0 and bc_off == 0:
                continue  # skip baseline
            cribs = build_crib_dict(ene_offset=ene_off, bc_offset=bc_off)
            best = best_periodic_score(cribs)

            # Also check Bean
            bean_results = {}
            for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
                eq_pass, ineq_pass, ineq_total = check_bean_constraints(cribs, variant)
                bean_results[variant] = {
                    'eq_pass': eq_pass,
                    'ineq_pass': ineq_pass,
                    'ineq_total': ineq_total,
                }

            entry = {
                'ene_offset': ene_off,
                'bc_offset': bc_off,
                'best_score': best['score'],
                'best_variant': best['variant'],
                'best_period': best['period'],
                'n_cribs': best['n_cribs'],
                'bean': bean_results,
            }
            block_results.append(entry)

            if best['score'] > baseline_best['score']:
                marker = " *** IMPROVEMENT ***"
            elif best['score'] == baseline_best['score']:
                marker = ""
            else:
                marker = ""

            print(f"  ENE{ene_off:+d} BC{bc_off:+d}: "
                  f"{best['score']}/{best['n_cribs']} "
                  f"({best['variant']}, p={best['period']}){marker}")

    results['block_shifts'] = block_results

    # Sort and show top block shifts
    block_results.sort(key=lambda x: x['best_score'], reverse=True)
    print(f"\n  Top 5 block shifts:")
    for entry in block_results[:5]:
        bean_note = ""
        for v in ['vigenere', 'beaufort']:
            if entry['bean'][v]['eq_pass']:
                bean_note += f" Bean({v})=PASS"
        print(f"    ENE{entry['ene_offset']:+d} BC{entry['bc_offset']:+d}: "
              f"{entry['best_score']}/{entry['n_cribs']} "
              f"({entry['best_variant']}, p={entry['best_period']}){bean_note}")

    # ── Test 2: ENE-only shifts at all periods ───────────────────────────
    print("\n--- Test 2: ENE-only shifts (detailed) ---")
    ene_detail = []
    for ene_off in range(-3, 4):
        cribs = build_crib_dict(ene_offset=ene_off, bc_offset=0)
        for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
            for period in range(2, 16):
                score = check_periodic_consistency(cribs, variant, period)
                if score >= baseline_best['score']:
                    eq_pass, ineq_pass, ineq_total = check_bean_constraints(cribs, variant)
                    ene_detail.append({
                        'ene_offset': ene_off,
                        'variant': variant,
                        'period': period,
                        'score': score,
                        'n_cribs': len(cribs),
                        'bean_eq': eq_pass,
                        'bean_ineq_pass': ineq_pass,
                    })

    ene_detail.sort(key=lambda x: x['score'], reverse=True)
    print(f"  Configs with score >= {baseline_best['score']}:")
    for entry in ene_detail[:10]:
        bean = "BeanEQ=PASS" if entry['bean_eq'] else "BeanEQ=FAIL"
        print(f"    ENE{entry['ene_offset']:+d}: {entry['score']}/{entry['n_cribs']} "
              f"({entry['variant']}, p={entry['period']}, {bean})")
    results['ene_detail'] = ene_detail

    # ── Test 3: BC-only shifts (detailed) ────────────────────────────────
    print("\n--- Test 3: BC-only shifts (detailed) ---")
    bc_detail = []
    for bc_off in range(-3, 4):
        cribs = build_crib_dict(ene_offset=0, bc_offset=bc_off)
        for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
            for period in range(2, 16):
                score = check_periodic_consistency(cribs, variant, period)
                if score >= baseline_best['score']:
                    eq_pass, ineq_pass, ineq_total = check_bean_constraints(cribs, variant)
                    bc_detail.append({
                        'bc_offset': bc_off,
                        'variant': variant,
                        'period': period,
                        'score': score,
                        'n_cribs': len(cribs),
                        'bean_eq': eq_pass,
                        'bean_ineq_pass': ineq_pass,
                    })

    bc_detail.sort(key=lambda x: x['score'], reverse=True)
    print(f"  Configs with score >= {baseline_best['score']}:")
    for entry in bc_detail[:10]:
        bean = "BeanEQ=PASS" if entry['bean_eq'] else "BeanEQ=FAIL"
        print(f"    BC{entry['bc_offset']:+d}: {entry['score']}/{entry['n_cribs']} "
              f"({entry['variant']}, p={entry['period']}, {bean})")
    results['bc_detail'] = bc_detail

    # ── Test 4: Drop individual positions and check improvement ──────────
    print("\n--- Test 4: Drop-one analysis ---")
    print("  If dropping one crib position improves the best periodic score,")
    print("  that position may be mis-indexed or the crib letter may be wrong.")

    drop_one_results = []
    for drop_pos in sorted(CRIB_DICT.keys()):
        cribs = {k: v for k, v in CRIB_DICT.items() if k != drop_pos}
        best = best_periodic_score(cribs)
        improvement = best['score'] - (baseline_best['score'] - 1)
        # -1 because dropping one crib reduces max possible by 1
        # So if best_score stays same or goes up, it's a true improvement
        drop_one_results.append({
            'dropped_pos': drop_pos,
            'dropped_char': CRIB_DICT[drop_pos],
            'ct_char': CT[drop_pos],
            'best_score': best['score'],
            'max_possible': len(cribs),
            'fraction': best['score'] / len(cribs),
            'best_variant': best['variant'],
            'best_period': best['period'],
        })
        marker = ""
        if best['score'] / len(cribs) > baseline_best['score'] / 24:
            marker = " <-- IMPROVED FRACTION"
        print(f"  Drop pos {drop_pos:2d} ({CRIB_DICT[drop_pos]}→{CT[drop_pos]}): "
              f"{best['score']}/{len(cribs)} = {best['score']/len(cribs):.3f} "
              f"({best['variant']}, p={best['period']}){marker}")

    results['drop_one'] = drop_one_results

    # ── Test 5: Self-encrypting position check ───────────────────────────
    print("\n--- Test 5: Self-encrypting positions ---")
    print("  Positions where CT[i] = PT[i] (key=0 for Vig, key=2*CT for Beau).")
    print("  These are independently verifiable constraints.")

    # Position 32: S->S (self-encrypting)
    # Position 73: K->K (self-encrypting)
    for pos in [32, 73]:
        ct_char = CT[pos]
        pt_char = CRIB_DICT[pos]
        print(f"  Pos {pos}: CT={ct_char}, PT={pt_char}, self-encrypt={ct_char==pt_char}")
        for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
            k = derive_key(pos, pt_char, variant)
            print(f"    {variant}: k={k} ({ALPH[k]})")

    # ── Test 6: Exhaustive per-position shifts ───────────────────────────
    print("\n--- Test 6: Per-position shift analysis ---")
    print("  For each crib position, shift it ±1 and check if score improves.")

    perpos_results = []
    for shift_pos in sorted(CRIB_DICT.keys()):
        pt_char = CRIB_DICT[shift_pos]
        for delta in [-2, -1, 1, 2]:
            new_pos = shift_pos + delta
            if new_pos < 0 or new_pos >= CT_LEN:
                continue
            # Build crib dict with this one position shifted
            cribs = dict(CRIB_DICT)
            del cribs[shift_pos]
            if new_pos not in cribs:  # Don't overwrite an existing crib
                cribs[new_pos] = pt_char
            else:
                continue

            best = best_periodic_score(cribs)
            if best['score'] >= baseline_best['score']:
                perpos_results.append({
                    'original_pos': shift_pos,
                    'new_pos': new_pos,
                    'delta': delta,
                    'pt_char': pt_char,
                    'score': best['score'],
                    'variant': best['variant'],
                    'period': best['period'],
                })

    perpos_results.sort(key=lambda x: x['score'], reverse=True)
    print(f"  Per-position shifts with score >= {baseline_best['score']}:")
    for entry in perpos_results[:15]:
        print(f"    Pos {entry['original_pos']}{entry['delta']:+d}→{entry['new_pos']}: "
              f"{entry['score']}/24 ({entry['variant']}, p={entry['period']})")
    results['perpos_shifts'] = perpos_results

    # ── Test 7: Key value analysis at shifted positions ──────────────────
    print("\n--- Test 7: Key values at top block shift configs ---")
    for ene_off, bc_off in [(-1, 0), (1, 0), (0, -1), (0, 1), (-1, -1), (1, 1)]:
        cribs = build_crib_dict(ene_offset=ene_off, bc_offset=bc_off)
        print(f"\n  ENE{ene_off:+d} BC{bc_off:+d} ({len(cribs)} cribs):")
        for variant in ['vigenere', 'beaufort']:
            keys = []
            for pos in sorted(cribs.keys()):
                if 0 <= pos < CT_LEN:
                    k = derive_key(pos, cribs[pos], variant)
                    keys.append((pos, k, ALPH[k]))
            key_str = " ".join(f"{ALPH[k]}" for _, k, _ in keys)
            key_vals = [k for _, k, _ in keys]

            # Check entropy
            counts = Counter(key_vals)
            import math
            entropy = -sum((c/len(key_vals)) * math.log2(c/len(key_vals))
                          for c in counts.values() if c > 0)

            print(f"    {variant}: key=[{key_str}] entropy={entropy:.2f} bits "
                  f"(max={math.log2(26):.2f})")

            # Check for most common key value
            mc = counts.most_common(3)
            mc_str = ", ".join(f"{ALPH[v]}({c})" for v, c in mc)
            print(f"    Most common: {mc_str}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Baseline best: {baseline_best['score']}/24 "
          f"({baseline_best['variant']}, p={baseline_best['period']})")

    # Best block shift
    if block_results:
        best_block = block_results[0]
        print(f"  Best block shift: {best_block['best_score']}/{best_block['n_cribs']} "
              f"(ENE{best_block['ene_offset']:+d} BC{best_block['bc_offset']:+d}, "
              f"{best_block['best_variant']}, p={best_block['best_period']})")

    # Best per-position shift
    if perpos_results:
        best_pp = perpos_results[0]
        print(f"  Best per-position shift: {best_pp['score']}/24 "
              f"(pos {best_pp['original_pos']}{best_pp['delta']:+d}, "
              f"{best_pp['variant']}, p={best_pp['period']})")

    # Check if any shift is dramatically better
    max_block = max(e['best_score'] for e in block_results) if block_results else 0
    max_perpos = max(e['score'] for e in perpos_results) if perpos_results else 0
    max_shifted = max(max_block, max_perpos)

    if max_shifted > baseline_best['score'] + 2:
        print(f"\n  *** POSSIBLE CRIB INDEXING ERROR ***")
        print(f"  Shifted score ({max_shifted}) exceeds baseline ({baseline_best['score']}) "
              f"by {max_shifted - baseline_best['score']} positions!")
    elif max_shifted > baseline_best['score']:
        print(f"\n  Minor improvement with shifted cribs (+{max_shifted - baseline_best['score']}), "
              f"possibly noise.")
    else:
        print(f"\n  No improvement from shifting cribs. Original positions appear correct.")

    # Drop-one analysis
    best_drop = max(drop_one_results, key=lambda x: x['fraction'])
    print(f"  Best drop-one: pos {best_drop['dropped_pos']} "
          f"({best_drop['dropped_char']}→{best_drop['ct_char']}), "
          f"{best_drop['best_score']}/{best_drop['max_possible']} = "
          f"{best_drop['fraction']:.3f}")

    print(f"\n  Runtime: {elapsed:.1f}s")

    verdict = "CRIB_POSITIONS_CORRECT"
    if max_shifted > baseline_best['score'] + 2:
        verdict = "POSSIBLE_CRIB_ERROR"
    elif max_shifted > baseline_best['score']:
        verdict = "MARGINAL_IMPROVEMENT"

    print(f"  Verdict: {verdict}")
    print(f"\nRESULT: best={max_shifted}/24 baseline={baseline_best['score']}/24 "
          f"verdict={verdict}")

    # Save results
    os.makedirs("results/frac", exist_ok=True)
    output = {
        'experiment': 'E-FRAC-18',
        'description': 'Crib position sensitivity analysis',
        'baseline': baseline_best,
        'block_shifts_top10': block_results[:10],
        'ene_detail_top10': ene_detail[:10],
        'bc_detail_top10': bc_detail[:10],
        'drop_one': drop_one_results,
        'perpos_shifts_top15': perpos_results[:15],
        'verdict': verdict,
        'max_shifted_score': max_shifted,
        'runtime': elapsed,
    }
    with open("results/frac/e_frac_18_crib_sensitivity.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"  Results written to results/frac/e_frac_18_crib_sensitivity.json")


if __name__ == "__main__":
    main()
