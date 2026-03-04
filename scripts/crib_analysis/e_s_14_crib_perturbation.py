#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: active
Keyspace: see implementation
Last run:
Best score:
attack(): yes
"""
"""E-S-14: Crib perturbation test.

Tests whether shifting any crib position by ±1 significantly improves
period consistency scores. If so, that position may be mis-indexed.

The persistent 14-17/24 ceiling across ALL cipher families could be explained
by incorrect crib positions rather than a transposition layer.

For each of the 24 crib positions:
1. Try shifting it by -1, 0, +1
2. For each shift, compute period consistency at periods 3-13
3. Compare against the baseline (no shift)

Also tests: removing each crib position entirely, to see if one position
is consistently the "bad apple" preventing higher scores.

Finally: tests all pairs of ±1 shifts on the two crib blocks independently.
"""

import json
import os
import sys
import time
from collections import Counter, defaultdict
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_CHARS = [c for _, c in _sorted]
PT_INT_LIST = [ord(c) - 65 for _, c in _sorted]
N_CRIBS = len(CRIB_POS)

# Separate into ENE and BC blocks
ENE_INDICES = [i for i, p in enumerate(CRIB_POS) if 20 <= p <= 35]
BC_INDICES = [i for i, p in enumerate(CRIB_POS) if 60 <= p <= 75]

ENE_POS = [CRIB_POS[i] for i in ENE_INDICES]
BC_POS = [CRIB_POS[i] for i in BC_INDICES]

print(f"ENE positions: {ENE_POS}")
print(f"BC positions: {BC_POS}")


def period_consistency(positions, pt_ints, period):
    """Compute period consistency score for given positions and PT values."""
    groups = defaultdict(list)
    for pos, pt_val in zip(positions, pt_ints):
        if 0 <= pos < CT_LEN:
            ct_val = CT_INT[pos]
            key_val = (ct_val - pt_val) % 26
            groups[pos % period].append(key_val)

    score = 0
    for vals in groups.values():
        if vals:
            score += Counter(vals).most_common(1)[0][1]
    return score


def period_consistency_beaufort(positions, pt_ints, period):
    """Beaufort variant."""
    groups = defaultdict(list)
    for pos, pt_val in zip(positions, pt_ints):
        if 0 <= pos < CT_LEN:
            ct_val = CT_INT[pos]
            key_val = (ct_val + pt_val) % 26
            groups[pos % period].append(key_val)

    score = 0
    for vals in groups.values():
        if vals:
            score += Counter(vals).most_common(1)[0][1]
    return score


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]

    Tests crib perturbation: individual ±1 shifts, block shifts.
    Score = best period_consistency score achieved by that configuration.
    Plaintext is empty (constraint analysis, not decryption).
    """
    ct_int_local = [ord(c) - 65 for c in ciphertext]
    ct_len_local = len(ciphertext)
    results: list[tuple[float, str, str]] = []

    # Baseline
    baseline = {}
    for period in range(3, 14):
        sv = period_consistency(CRIB_POS, PT_INT_LIST, period)
        sb = period_consistency_beaufort(CRIB_POS, PT_INT_LIST, period)
        baseline[period] = {"vig": sv, "beau": sb}

    # Individual position shifts
    for idx in range(N_CRIBS):
        orig_pos = CRIB_POS[idx]
        char = CRIB_CHARS[idx]
        for shift in [-1, 1]:
            new_pos = orig_pos + shift
            if new_pos < 0 or new_pos >= ct_len_local:
                continue
            mod_pos = list(CRIB_POS)
            mod_pos[idx] = new_pos
            mod_pt = list(PT_INT_LIST)
            if len(set(mod_pos)) < len(mod_pos):
                continue
            best_score = 0
            best_detail = ""
            for period in range(3, 14):
                for variant, func in [('vig', period_consistency),
                                       ('beau', period_consistency_beaufort)]:
                    score = func(mod_pos, mod_pt, period)
                    if score > best_score:
                        best_score = score
                        best_detail = f"p={period} {variant}"
            method = (f"crib-perturb pos={orig_pos}({char}) shift={shift:+d} "
                      f"best={best_detail}")
            results.append((float(best_score), "", method))

    # Block shifts
    for ene_shift in range(-3, 4):
        for bc_shift in range(-3, 4):
            if ene_shift == 0 and bc_shift == 0:
                continue
            mod_pos = list(CRIB_POS)
            for i in ENE_INDICES:
                mod_pos[i] = CRIB_POS[i] + ene_shift
            for i in BC_INDICES:
                mod_pos[i] = CRIB_POS[i] + bc_shift
            if any(p < 0 or p >= ct_len_local for p in mod_pos):
                continue
            if len(set(mod_pos)) < len(mod_pos):
                continue
            best_score = 0
            best_detail = ""
            for period in range(3, 14):
                for variant, func in [('vig', period_consistency),
                                       ('beau', period_consistency_beaufort)]:
                    score = func(mod_pos, PT_INT_LIST, period)
                    if score > best_score:
                        best_score = score
                        best_detail = f"p={period} {variant}"
            method = (f"crib-block ENE{ene_shift:+d} BC{bc_shift:+d} "
                      f"best={best_detail}")
            results.append((float(best_score), "", method))

    results.sort(key=lambda x: -x[0])
    return results


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-14: Crib Perturbation Test")
    print("=" * 60)
    print(f"Crib positions: {N_CRIBS} (ENE: {len(ENE_INDICES)}, BC: {len(BC_INDICES)})")
    print(f"Testing: individual shifts ±1, removal, block shifts")
    print()

    # ═══ Baseline ═════════════════════════════════════════════════════════
    print("Phase 1: Baseline scores")
    print("-" * 40)

    baseline = {}
    for period in range(3, 14):
        sv = period_consistency(CRIB_POS, PT_INT_LIST, period)
        sb = period_consistency_beaufort(CRIB_POS, PT_INT_LIST, period)
        baseline[period] = {"vig": sv, "beau": sb}
        print(f"  p={period:>2}: vig={sv}/24  beau={sb}/24")

    # ═══ Individual position shifts ═══════════════════════════════════════
    print("\nPhase 2: Individual position shifts (±1)")
    print("-" * 40)

    individual_results = []

    for idx in range(N_CRIBS):
        orig_pos = CRIB_POS[idx]
        char = CRIB_CHARS[idx]

        for shift in [-1, 0, 1]:
            new_pos = orig_pos + shift
            if new_pos < 0 or new_pos >= CT_LEN:
                continue
            if shift == 0:
                continue  # baseline

            # Build modified position list
            mod_pos = list(CRIB_POS)
            mod_pos[idx] = new_pos
            mod_pt = list(PT_INT_LIST)  # PT values stay the same

            # Check for duplicates (two cribs at same position)
            if len(set(mod_pos)) < len(mod_pos):
                continue

            best_improvement = -99
            best_config = None

            for period in range(3, 14):
                for variant, func in [('vig', period_consistency),
                                       ('beau', period_consistency_beaufort)]:
                    score = func(mod_pos, mod_pt, period)
                    base = baseline[period][variant]
                    improvement = score - base

                    if improvement > best_improvement:
                        best_improvement = improvement
                        best_config = {
                            "period": period, "variant": variant,
                            "score": score, "base": base,
                        }

            entry = {
                "crib_idx": idx, "orig_pos": orig_pos, "char": char,
                "shift": shift, "new_pos": new_pos,
                "best_improvement": best_improvement,
                "best_config": best_config,
            }
            individual_results.append(entry)

            if best_improvement > 0:
                print(f"  pos {orig_pos}({char}) shift={shift:+d} → "
                      f"pos {new_pos}: improvement={best_improvement:+d} "
                      f"({best_config['score']}/{N_CRIBS} at p={best_config['period']} "
                      f"{best_config['variant']})")

    # ═══ Individual removal ═══════════════════════════════════════════════
    print("\nPhase 3: Individual crib removal (which position hurts most?)")
    print("-" * 40)

    removal_results = []

    for idx in range(N_CRIBS):
        orig_pos = CRIB_POS[idx]
        char = CRIB_CHARS[idx]

        # Remove this crib
        mod_pos = [CRIB_POS[i] for i in range(N_CRIBS) if i != idx]
        mod_pt = [PT_INT_LIST[i] for i in range(N_CRIBS) if i != idx]
        n_remaining = len(mod_pos)

        # For fair comparison, we need baseline without this crib too
        # Actually, what matters is: fraction of matches
        best_frac_improvement = -99
        best_config = None

        for period in range(3, 14):
            for variant, func in [('vig', period_consistency),
                                   ('beau', period_consistency_beaufort)]:
                score = func(mod_pos, mod_pt, period)
                base = baseline[period][variant]

                # Compare: score/(N-1) vs base/N
                frac_new = score / n_remaining
                frac_base = base / N_CRIBS
                improvement = frac_new - frac_base

                if improvement > best_frac_improvement:
                    best_frac_improvement = improvement
                    best_config = {
                        "period": period, "variant": variant,
                        "score": score, "n": n_remaining,
                        "frac": round(frac_new, 3),
                        "base_frac": round(frac_base, 3),
                    }

        entry = {
            "crib_idx": idx, "orig_pos": orig_pos, "char": char,
            "best_frac_improvement": round(best_frac_improvement, 3),
            "best_config": best_config,
        }
        removal_results.append(entry)

    # Sort by improvement
    removal_results.sort(key=lambda x: -x["best_frac_improvement"])
    print("  Crib positions sorted by fractional improvement when removed:")
    for r in removal_results[:10]:
        print(f"  pos {r['orig_pos']:>2}({r['char']}): frac_improvement={r['best_frac_improvement']:+.3f} "
              f"({r['best_config']['score']}/{r['best_config']['n']} at "
              f"p={r['best_config']['period']} {r['best_config']['variant']})")

    # ═══ Block shifts ═════════════════════════════════════════════════════
    print("\nPhase 4: Block shifts (shift entire ENE or BC block)")
    print("-" * 40)

    block_results = []

    for ene_shift in range(-3, 4):
        for bc_shift in range(-3, 4):
            if ene_shift == 0 and bc_shift == 0:
                continue

            mod_pos = list(CRIB_POS)
            for i in ENE_INDICES:
                mod_pos[i] = CRIB_POS[i] + ene_shift
            for i in BC_INDICES:
                mod_pos[i] = CRIB_POS[i] + bc_shift

            # Check bounds
            if any(p < 0 or p >= CT_LEN for p in mod_pos):
                continue
            if len(set(mod_pos)) < len(mod_pos):
                continue

            best_score = 0
            best_config = None

            for period in range(3, 14):
                for variant, func in [('vig', period_consistency),
                                       ('beau', period_consistency_beaufort)]:
                    score = func(mod_pos, PT_INT_LIST, period)
                    base = baseline[period][variant]

                    if score > best_score:
                        best_score = score
                        best_config = {
                            "period": period, "variant": variant,
                            "score": score, "base": base,
                            "improvement": score - base,
                        }

            entry = {
                "ene_shift": ene_shift, "bc_shift": bc_shift,
                "best_score": best_score, "best_config": best_config,
            }
            block_results.append(entry)

    block_results.sort(key=lambda x: -x["best_score"])
    print("  Top 10 block shift combinations:")
    for i, r in enumerate(block_results[:10]):
        cfg = r["best_config"]
        print(f"  {i+1:>2}. ENE{r['ene_shift']:+d} BC{r['bc_shift']:+d}: "
              f"score={r['best_score']}/24  "
              f"improvement={cfg['improvement']:+d}  "
              f"p={cfg['period']} {cfg['variant']}")

    # ═══ Bean constraint check on shifts ═════════════════════════════════
    print("\nPhase 5: Bean constraint check on shifted positions")
    print("-" * 40)

    # Bean equality: k[27] = k[65] under standard indexing
    # If ENE shifts by e and BC shifts by b:
    # k[27+e] should equal k[65+b]
    # In Vigenère: (CT[27+e] - PT_at_that_position) = (CT[65+b] - PT_at_that_position)
    # But PT assignment also shifts with the block!

    # Original: pos 27 → 'R' (index 6 in ENE), pos 65 → 'R' (index 2 in BC)
    ene_r_idx = None  # index within ENE_INDICES where position = 27
    bc_r_idx = None   # index within BC_INDICES where position = 65

    for i, idx in enumerate(ENE_INDICES):
        if CRIB_POS[idx] == 27:
            ene_r_idx = idx
            break
    for i, idx in enumerate(BC_INDICES):
        if CRIB_POS[idx] == 65:
            bc_r_idx = idx
            break

    if ene_r_idx is not None and bc_r_idx is not None:
        print(f"  Bean positions: 27 (ENE, PT='R'), 65 (BC, PT='R')")
        print(f"  CT[27]={CT[27]}={CT_INT[27]}, CT[65]={CT[65]}={CT_INT[65]}")

        for ene_shift in range(-3, 4):
            for bc_shift in range(-3, 4):
                p1 = 27 + ene_shift
                p2 = 65 + bc_shift
                if p1 < 0 or p1 >= CT_LEN or p2 < 0 or p2 >= CT_LEN:
                    continue

                # Vigenère key values
                k1_v = (CT_INT[p1] - PT_INT_LIST[ene_r_idx]) % 26
                k2_v = (CT_INT[p2] - PT_INT_LIST[bc_r_idx]) % 26
                bean_vig = (k1_v == k2_v)

                # Beaufort key values
                k1_b = (CT_INT[p1] + PT_INT_LIST[ene_r_idx]) % 26
                k2_b = (CT_INT[p2] + PT_INT_LIST[bc_r_idx]) % 26
                bean_beau = (k1_b == k2_b)

                if bean_vig or bean_beau:
                    tag = []
                    if bean_vig:
                        tag.append(f"vig(k={k1_v})")
                    if bean_beau:
                        tag.append(f"beau(k={k1_b})")
                    print(f"  ENE{ene_shift:+d} BC{bc_shift:+d}: "
                          f"Bean PASS — {', '.join(tag)}")

    # ═══ Summary ═════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Time: {elapsed:.3f}s")

    # Did any individual shift improve scores?
    pos_shifts = [r for r in individual_results if r["best_improvement"] > 0]
    print(f"\n  Individual shifts with improvement: {len(pos_shifts)}/{len(individual_results)}")
    if pos_shifts:
        pos_shifts.sort(key=lambda x: -x["best_improvement"])
        for r in pos_shifts[:5]:
            print(f"    pos {r['orig_pos']}({r['char']}) shift={r['shift']:+d}: "
                  f"+{r['best_improvement']} ({r['best_config']['score']}/{N_CRIBS})")

    # Best block shift
    if block_results:
        best_block = block_results[0]
        baseline_max = max(max(baseline[p]["vig"], baseline[p]["beau"]) for p in range(3, 14))
        print(f"\n  Best block shift: ENE{best_block['ene_shift']:+d} "
              f"BC{best_block['bc_shift']:+d} → {best_block['best_score']}/24 "
              f"(baseline max: {baseline_max}/24)")

    # Verdict
    max_improvement = max((r["best_improvement"] for r in individual_results), default=0)
    if max_improvement >= 3:
        verdict = "CRIB ERROR LIKELY"
    elif max_improvement >= 2:
        verdict = "INVESTIGATE CRIB POSITIONS"
    elif max_improvement >= 1:
        verdict = "MINOR IMPROVEMENT — likely noise"
    else:
        verdict = "NO EVIDENCE OF CRIB ERROR"

    print(f"\n  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_14_crib_perturbation.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-14",
            "hypothesis": "One or more crib positions may be mis-indexed by ±1",
            "total_time_s": round(elapsed, 3),
            "verdict": verdict,
            "baseline": {str(k): v for k, v in baseline.items()},
            "individual_shifts": individual_results,
            "removal_results": removal_results,
            "block_shifts_top10": block_results[:10],
            "max_individual_improvement": max_improvement,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_14_crib_perturbation.py")
    print(f"\nRESULT: max_improvement={max_improvement} verdict={verdict}")

    # ── Print attack() results ────────────────────────────────────────────
    attack_results = attack(CT)
    if attack_results:
        print(f"\n── attack() top results ─────────────────────────────────────────")
        for score, pt, method in attack_results[:10]:
            print(f"  {score:5.1f}  {method}")


if __name__ == "__main__":
    main()
