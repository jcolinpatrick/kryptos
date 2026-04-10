#!/usr/bin/env python3
"""TABP diagnostic — count rejections at each filter stage.

Runs the TABP filter on a small sample of transpositions and reports
how many (T, period, variant) combinations are rejected at each stage.
Confirms the hot path is actually exercising scoring, not silently
short-circuiting.

NOT A CAMPAIGN — diagnostic only.
"""
from __future__ import annotations

import os
import sys
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT, CT_LEN, MOD, STORE_THRESHOLD,
)
from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
from kryptos.kernel.scoring.aggregate import score_candidate_free

# Import enumeration from the campaign
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from f_tabp_transposition_outer_v1 import (
    enumerate_all_transpositions, _compute_implied_keys, _decrypt_tabp,
    MAX_PERIOD, VARIANTS,
)


def diagnose(sample_size: int = 200) -> None:
    all_ts = enumerate_all_transpositions()
    print(f"Total enumerated: {len(all_ts)}")
    print(f"Diagnosing first {sample_size} Ts with full stage tracking\n")

    sample = all_ts[:sample_size]

    stats = {
        "total_ts": 0,
        "bean_derived": 0,
        "total_t_period_pairs": 0,
        "bean_ineq_pass": 0,
        "total_t_period_variant": 0,
        "period_consistent": 0,
        "no_missing_residues": 0,
        "decrypted": 0,
        "scored": 0,
        "survivors_at_10": 0,
        "survivors_at_18": 0,
        "max_score": 0,
        "ineq_count_dist": [],
        "eq_count_dist": [],
    }

    for label, pt_to_ct in sample:
        stats["total_ts"] += 1
        try:
            eq, ineq = rederive_bean_for_transposition(pt_to_ct)
        except Exception as e:
            print(f"  ERROR rederiving for {label}: {e}")
            continue
        stats["bean_derived"] += 1
        stats["ineq_count_dist"].append(len(ineq))
        stats["eq_count_dist"].append(len(eq))

        for period in range(1, MAX_PERIOD + 1):
            stats["total_t_period_pairs"] += 1
            # Bean INEQ pre-filter
            violated = any((a % period) == (b % period) for a, b in ineq)
            if violated:
                continue
            stats["bean_ineq_pass"] += 1

            for variant in VARIANTS:
                stats["total_t_period_variant"] += 1
                implied = _compute_implied_keys(pt_to_ct, variant)

                residue_values = {}
                consistent = True
                for pos, val in implied.items():
                    r = pos % period
                    existing = residue_values.get(r)
                    if existing is None:
                        residue_values[r] = val
                    elif existing != val:
                        consistent = False
                        break
                if not consistent:
                    continue
                stats["period_consistent"] += 1

                missing = [r for r in range(period) if r not in residue_values]
                if not missing:
                    stats["no_missing_residues"] += 1
                    key_candidates = [dict(residue_values)]
                elif len(missing) <= 3:
                    key_candidates = []
                    for vals in product(range(MOD), repeat=len(missing)):
                        kv = dict(residue_values)
                        for r, v in zip(missing, vals):
                            kv[r] = v
                        key_candidates.append(kv)
                else:
                    continue

                for kv in key_candidates:
                    keystream = [kv[i % period] for i in range(CT_LEN)]
                    pt = _decrypt_tabp(pt_to_ct, variant, keystream)
                    stats["decrypted"] += 1
                    breakdown = score_candidate_free(pt)
                    stats["scored"] += 1
                    stats["max_score"] = max(stats["max_score"], breakdown.crib_score)
                    if breakdown.crib_score >= 10:
                        stats["survivors_at_10"] += 1
                    if breakdown.crib_score >= 18:
                        stats["survivors_at_18"] += 1

    print("=== STAGE-BY-STAGE REJECTION COUNTS ===")
    print(f"Total Ts processed:        {stats['total_ts']}")
    print(f"Bean derivations succeeded: {stats['bean_derived']}")
    print()
    if stats["ineq_count_dist"]:
        d = stats["ineq_count_dist"]
        print(f"INEQ count distribution:   "
              f"min={min(d)}, max={max(d)}, mean={sum(d)/len(d):.1f}")
        e = stats["eq_count_dist"]
        print(f"EQ count distribution:     "
              f"min={min(e)}, max={max(e)}, mean={sum(e)/len(e):.2f}")
    print()
    print(f"(T, period) total:         {stats['total_t_period_pairs']}")
    print(f"(T, period) passed Bean INEQ: {stats['bean_ineq_pass']} "
          f"({100 * stats['bean_ineq_pass'] / max(1, stats['total_t_period_pairs']):.2f}%)")
    print()
    print(f"(T, period, variant) total: {stats['total_t_period_variant']}")
    print(f"  period-consistent:        {stats['period_consistent']} "
          f"({100 * stats['period_consistent'] / max(1, stats['total_t_period_variant']):.2f}%)")
    print(f"  no missing residues:      {stats['no_missing_residues']}")
    print()
    print(f"Total decryptions:         {stats['decrypted']}")
    print(f"Total scored:              {stats['scored']}")
    print(f"Max crib score seen:       {stats['max_score']}/24")
    print(f"Survivors >= 10:           {stats['survivors_at_10']}")
    print(f"Survivors >= 18:           {stats['survivors_at_18']}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--sample", type=int, default=200)
    args = p.parse_args()
    diagnose(args.sample)
