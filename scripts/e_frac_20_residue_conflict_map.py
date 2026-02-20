#!/usr/bin/env python3
"""E-FRAC-20: Residue Conflict Map — Which Crib Positions Block Full Score?

For each period p (2-7) and cipher variant, identify exactly which crib
positions are inconsistent with the majority-vote key. These "conflict positions"
tell us:
1. Which positions a transposition would need to move to improve the score
2. Whether conflicts cluster (suggesting block transposition) or scatter
3. Whether ENE and BC positions behave differently

This analysis guides TRANS/JTS agents by showing WHERE the blockage is.

Also: Monte Carlo analysis of conflict patterns to determine if the
observed pattern is unusual (suggesting partial transposition) vs random.
"""

import json
import math
import os
import random
import time
from collections import Counter
from itertools import combinations

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD, ALPH_IDX, CRIB_DICT,
    BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)


def derive_key(ct_pos: int, pt_char: str, variant: str) -> int:
    """Derive key value at a position."""
    ct_val = ALPH_IDX[CT[ct_pos]]
    pt_val = ALPH_IDX[pt_char]
    if variant == 'vigenere':
        return (ct_val - pt_val) % MOD
    elif variant == 'beaufort':
        return (ct_val + pt_val) % MOD
    elif variant == 'variant_beaufort':
        return (pt_val - ct_val) % MOD
    raise ValueError(f"Unknown variant: {variant}")


def get_conflict_map(crib_dict: dict, variant: str, period: int) -> dict:
    """Get detailed conflict map for a given period and variant.

    Returns dict with:
    - total_matches: number of crib positions consistent with majority key
    - residue_details: per-residue breakdown
    - conflict_positions: list of positions that don't match majority
    - match_positions: list of positions that do match
    """
    # Group key values by residue class
    residues = {}
    for pos in sorted(crib_dict.keys()):
        k = derive_key(pos, crib_dict[pos], variant)
        r = pos % period
        if r not in residues:
            residues[r] = []
        residues[r].append((pos, k))

    total_matches = 0
    conflict_positions = []
    match_positions = []
    residue_details = {}

    for r in sorted(residues.keys()):
        entries = residues[r]
        if len(entries) == 0:
            continue

        key_counts = Counter(k for _, k in entries)
        majority_key, majority_count = key_counts.most_common(1)[0]
        total_matches += majority_count

        conflicts = [(pos, k) for pos, k in entries if k != majority_key]
        matches = [(pos, k) for pos, k in entries if k == majority_key]

        conflict_positions.extend(pos for pos, _ in conflicts)
        match_positions.extend(pos for pos, _ in matches)

        residue_details[r] = {
            'majority_key': majority_key,
            'majority_key_letter': ALPH[majority_key],
            'majority_count': majority_count,
            'total': len(entries),
            'conflicts': [(pos, k, ALPH[k]) for pos, k in conflicts],
            'matches': [pos for pos, _ in matches],
        }

    return {
        'total_matches': total_matches,
        'total_cribs': len(crib_dict),
        'conflict_positions': sorted(conflict_positions),
        'match_positions': sorted(match_positions),
        'residue_details': residue_details,
        'n_conflicts': len(conflict_positions),
    }


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-20: Residue Conflict Map")
    print("=" * 70)

    results = {}
    crib_dict = dict(CRIB_DICT)
    crib_positions = sorted(crib_dict.keys())

    # ── Section 1: Conflict maps for all periods and variants ────────────
    print("\n--- Section 1: Conflict maps (periods 2-7, all variants) ---")
    print("  Showing which crib positions conflict with majority-vote key.\n")

    all_maps = {}
    for variant in ['vigenere', 'beaufort', 'variant_beaufort']:
        for period in range(2, 8):
            cmap = get_conflict_map(crib_dict, variant, period)
            key = f"{variant}_p{period}"
            all_maps[key] = cmap

            if cmap['total_matches'] >= 10:  # Only show interesting configs
                conflicts = cmap['conflict_positions']
                ene_conflicts = [p for p in conflicts if 21 <= p <= 33]
                bc_conflicts = [p for p in conflicts if 63 <= p <= 73]

                print(f"  {variant} p={period}: {cmap['total_matches']}/24 matches, "
                      f"{cmap['n_conflicts']} conflicts")
                print(f"    Conflicts: {conflicts}")
                print(f"    ENE conflicts: {len(ene_conflicts)}/13, "
                      f"BC conflicts: {len(bc_conflicts)}/11")

    results['conflict_maps'] = {
        k: {kk: vv for kk, vv in v.items() if kk != 'residue_details'}
        for k, v in all_maps.items()
    }

    # ── Section 2: Best configs with detailed residue breakdown ──────────
    print("\n--- Section 2: Best configs (detailed residue breakdown) ---")

    # Sort by matches
    sorted_configs = sorted(all_maps.items(), key=lambda x: -x[1]['total_matches'])

    for key, cmap in sorted_configs[:6]:
        print(f"\n  === {key}: {cmap['total_matches']}/24 ===")
        for r in sorted(cmap['residue_details'].keys()):
            rd = cmap['residue_details'][r]
            conflict_str = ""
            if rd['conflicts']:
                conflict_str = " CONFLICTS: " + ", ".join(
                    f"pos{pos}({letter})" for pos, k, letter in rd['conflicts'])
            print(f"    Residue {r}: majority={rd['majority_key_letter']}({rd['majority_key']}), "
                  f"{rd['majority_count']}/{rd['total']}{conflict_str}")

    # ── Section 3: Conflict position frequency ───────────────────────────
    print("\n--- Section 3: Which positions conflict most often? ---")
    print("  (Across all period/variant combinations with ≥10 matches)")

    position_conflict_count = Counter()
    n_configs_counted = 0

    for key, cmap in all_maps.items():
        if cmap['total_matches'] >= 10:
            n_configs_counted += 1
            for pos in cmap['conflict_positions']:
                position_conflict_count[pos] += 1

    print(f"  Across {n_configs_counted} configs:")
    print(f"  {'Pos':>4} {'CT':>3} {'PT':>3} {'Conflicts':>9} {'Rate':>6} {'Region':>10}")
    print(f"  {'-'*40}")
    for pos in crib_positions:
        count = position_conflict_count.get(pos, 0)
        rate = count / n_configs_counted if n_configs_counted > 0 else 0
        region = "ENE" if 21 <= pos <= 33 else "BC"
        marker = " ***" if rate > 0.8 else ""
        print(f"  {pos:>4} {CT[pos]:>3} {crib_dict[pos]:>3} {count:>9} {rate:>6.2f} {region:>10}{marker}")

    results['conflict_frequency'] = {
        pos: position_conflict_count.get(pos, 0) for pos in crib_positions
    }

    # ── Section 4: ENE vs BC conflict asymmetry ──────────────────────────
    print("\n--- Section 4: ENE vs BC conflict asymmetry ---")

    for key, cmap in sorted_configs[:8]:
        conflicts = cmap['conflict_positions']
        ene_c = sum(1 for p in conflicts if 21 <= p <= 33)
        bc_c = sum(1 for p in conflicts if 63 <= p <= 73)
        ene_rate = ene_c / 13
        bc_rate = bc_c / 11

        print(f"  {key}: ENE={ene_c}/13 ({ene_rate:.0%}), "
              f"BC={bc_c}/11 ({bc_rate:.0%}), "
              f"ratio={ene_rate/bc_rate:.2f}" if bc_rate > 0 else
              f"  {key}: ENE={ene_c}/13 ({ene_rate:.0%}), BC=0/11")

    # ── Section 5: Monte Carlo — Is the conflict pattern unusual? ────────
    print("\n--- Section 5: Monte Carlo conflict pattern analysis ---")
    print("  Are the K4 conflict patterns unusual compared to random CT?")

    n_mc = 10000
    best_config = sorted_configs[0]
    best_key = best_config[0]
    best_matches = best_config[1]['total_matches']
    parts = best_key.split('_')
    best_variant = parts[0]
    best_period = int(parts[1][1:])

    print(f"  Testing {best_key} (score={best_matches}) against random CT...")

    mc_scores = []
    mc_ene_conflicts = []
    mc_bc_conflicts = []

    for _ in range(n_mc):
        # Generate random CT of length 97
        rand_ct = ''.join(random.choice(ALPH) for _ in range(CT_LEN))

        # Compute key values at crib positions
        residues = {}
        for pos in crib_positions:
            ct_val = ALPH_IDX[rand_ct[pos]]
            pt_val = ALPH_IDX[crib_dict[pos]]
            if best_variant == 'vigenere':
                k = (ct_val - pt_val) % MOD
            elif best_variant == 'beaufort':
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD

            r = pos % best_period
            if r not in residues:
                residues[r] = []
            residues[r].append((pos, k))

        total = 0
        conflicts = []
        for r, entries in residues.items():
            if entries:
                key_counts = Counter(k for _, k in entries)
                majority_count = key_counts.most_common(1)[0][1]
                total += majority_count
                for pos, k in entries:
                    if k != key_counts.most_common(1)[0][0]:
                        conflicts.append(pos)

        mc_scores.append(total)
        mc_ene_conflicts.append(sum(1 for p in conflicts if 21 <= p <= 33))
        mc_bc_conflicts.append(sum(1 for p in conflicts if 63 <= p <= 73))

    mc_scores.sort()
    mean_mc = sum(mc_scores) / len(mc_scores)
    std_mc = math.sqrt(sum((s - mean_mc) ** 2 for s in mc_scores) / len(mc_scores))
    pctile = sum(1 for s in mc_scores if s <= best_matches) / n_mc * 100
    z_score = (best_matches - mean_mc) / std_mc if std_mc > 0 else 0

    print(f"  K4 score: {best_matches}/24")
    print(f"  Random CT: mean={mean_mc:.1f}, std={std_mc:.2f}")
    print(f"  K4 percentile: {pctile:.1f}%")
    print(f"  Z-score: {z_score:.2f}")

    # ENE/BC conflict ratio
    k4_ene_c = sum(1 for p in best_config[1]['conflict_positions'] if 21 <= p <= 33)
    k4_bc_c = sum(1 for p in best_config[1]['conflict_positions'] if 63 <= p <= 73)
    mean_ene = sum(mc_ene_conflicts) / len(mc_ene_conflicts)
    mean_bc = sum(mc_bc_conflicts) / len(mc_bc_conflicts)

    print(f"\n  ENE conflict count: K4={k4_ene_c}, random mean={mean_ene:.1f}")
    print(f"  BC conflict count: K4={k4_bc_c}, random mean={mean_bc:.1f}")

    results['monte_carlo'] = {
        'config': best_key,
        'k4_score': best_matches,
        'mc_mean': mean_mc,
        'mc_std': std_mc,
        'percentile': pctile,
        'z_score': z_score,
    }

    # ── Section 6: Identifying "pivot positions" ─────────────────────────
    print("\n--- Section 6: Pivot positions ---")
    print("  If we could change ONE crib position's key value to the majority,")
    print("  which single change would most improve the score?")

    for key, cmap in sorted_configs[:3]:
        print(f"\n  {key} (current: {cmap['total_matches']}/24):")
        for pos in cmap['conflict_positions']:
            # What would the score be if this position matched?
            test_score = cmap['total_matches'] + 1

            # Check: does removing this position create cascading benefits?
            parts = key.split('_')
            variant = parts[0]
            period = int(parts[1][1:])
            r = pos % period
            rd = cmap['residue_details'][r]

            # How many positions share this residue?
            n_in_residue = rd['total']
            n_conflicts_in_residue = len(rd['conflicts'])

            k = derive_key(pos, crib_dict[pos], variant)
            print(f"    Pos {pos} ({crib_dict[pos]}→{CT[pos]}): key={k}({ALPH[k]}), "
                  f"residue {r} has {n_conflicts_in_residue}/{n_in_residue} conflicts, "
                  f"majority={rd['majority_key_letter']}({rd['majority_key']})")

    # ── Section 7: Bean constraint interaction ───────────────────────────
    print("\n--- Section 7: Bean constraint interaction with conflicts ---")
    print("  Do Bean-relevant positions appear in conflict sets?")

    bean_positions = set()
    for eq_a, eq_b in BEAN_EQ:
        bean_positions.add(eq_a)
        bean_positions.add(eq_b)
    for ineq_a, ineq_b in BEAN_INEQ:
        bean_positions.add(ineq_a)
        bean_positions.add(ineq_b)

    bean_crib_positions = bean_positions & set(crib_positions)
    print(f"  Bean-relevant crib positions: {sorted(bean_crib_positions)}")

    for key, cmap in sorted_configs[:3]:
        bean_conflicts = set(cmap['conflict_positions']) & bean_crib_positions
        print(f"  {key}: {len(bean_conflicts)} Bean positions in conflict: "
              f"{sorted(bean_conflicts)}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")

    best_key, best_cmap = sorted_configs[0]
    print(f"  Best config: {best_key} ({best_cmap['total_matches']}/24)")
    print(f"  Conflict positions: {best_cmap['conflict_positions']}")
    print(f"  ENE conflicts: {sum(1 for p in best_cmap['conflict_positions'] if 21<=p<=33)}/13")
    print(f"  BC conflicts: {sum(1 for p in best_cmap['conflict_positions'] if 63<=p<=73)}/11")
    print(f"  K4 percentile vs random: {pctile:.1f}%")
    print(f"  Z-score vs random: {z_score:.2f}")

    # Positions that conflict most often
    always_conflict = [pos for pos in crib_positions
                       if position_conflict_count.get(pos, 0) > 0.8 * n_configs_counted]
    print(f"\n  Positions that conflict >80% of the time: {always_conflict}")
    rarely_conflict = [pos for pos in crib_positions
                       if position_conflict_count.get(pos, 0) < 0.3 * n_configs_counted]
    print(f"  Positions that conflict <30% of the time: {rarely_conflict}")

    if z_score > 2:
        verdict = "K4_SCORE_UNUSUAL"
    else:
        verdict = "K4_CONSISTENT_WITH_RANDOM"

    print(f"\n  Verdict: {verdict}")
    print(f"  Runtime: {elapsed:.1f}s")
    print(f"\nRESULT: best={best_cmap['total_matches']}/24 z={z_score:.2f} verdict={verdict}")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    # Simplify residue details for JSON serialization
    simplified_maps = {}
    for key, cmap in sorted_configs[:10]:
        simplified = {k: v for k, v in cmap.items() if k != 'residue_details'}
        simplified['residue_summary'] = {
            str(r): {
                'majority': rd['majority_key_letter'],
                'count': f"{rd['majority_count']}/{rd['total']}",
                'conflicts': [(pos, letter) for pos, _, letter in rd['conflicts']],
            }
            for r, rd in cmap['residue_details'].items()
        }
        simplified_maps[key] = simplified

    output = {
        'experiment': 'E-FRAC-20',
        'description': 'Residue conflict map — which crib positions block full score',
        'top_configs': simplified_maps,
        'conflict_frequency': results['conflict_frequency'],
        'monte_carlo': results['monte_carlo'],
        'verdict': verdict,
        'runtime': elapsed,
    }
    with open("results/frac/e_frac_20_residue_conflict_map.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"  Results written to results/frac/e_frac_20_residue_conflict_map.json")


if __name__ == "__main__":
    main()
