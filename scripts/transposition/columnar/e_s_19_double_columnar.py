#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: transposition/columnar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-19: Double Columnar Transposition + Periodic Vigenère/Beaufort

Tests the compound cipher: double columnar transposition + periodic substitution.
Double columnar was widely used by real military systems (SOE, WWII).

Model A: CT = σ(Vig(PT, key))  — encrypt then transpose
Model B: CT = Vig(σ(PT), key)  — transpose then encrypt

Where σ = col2 ∘ col1 (two successive columnar transpositions).

Exhaustive for width pairs (w1,w2) with w1,w2 in {5,6,7}.
Primary discriminator: period 7 (noise floor ~8.2/24).
Top candidates re-checked at periods 3-8.

Output: results/e_s_19_double_columnar.json
"""
import itertools
import json
import math
import sys
import time
from collections import defaultdict

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, N_CRIBS, CRIB_DICT, ALPH_IDX, MOD,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)

CT_NUM = tuple(ALPH_IDX[c] for c in CT)
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = [ALPH_IDX[CRIB_DICT[p]] for p in CRIB_POS]
N_CRIB = len(CRIB_POS)

# Precompute residue groups for Model A at period 7
MODEL_A_GROUPS_P7 = [[] for _ in range(7)]
for idx, j in enumerate(CRIB_POS):
    MODEL_A_GROUPS_P7[j % 7].append(idx)


def columnar_encrypt_perm(n, width, col_order):
    """Gather-convention permutation for columnar transposition.
    output[i] = input[perm[i]]."""
    perm = []
    for col in col_order:
        if n % width == 0:
            col_len = n // width
        elif col < (n % width):
            col_len = (n // width) + 1
        else:
            col_len = n // width
        for row in range(col_len):
            perm.append(row * width + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def precompute_all_perms(width, n=CT_LEN):
    """Precompute all columnar permutations and their inverses for a given width."""
    perms = []
    for order in itertools.permutations(range(width)):
        p = columnar_encrypt_perm(n, width, list(order))
        p_inv = invert_perm(p)
        perms.append((list(order), p, p_inv))
    return perms


def score_at_period(ct_vals, mapped_positions, period, model_a=True):
    """Score crib consistency for both Vigenère and Beaufort.

    ct_vals: CT values at the 24 mapped positions
    mapped_positions: the 24 output positions (for Model B grouping)
    model_a: if True, group by original crib position mod p; else by mapped position mod p

    Returns (vig_score, beau_score).
    """
    vig_bins = [dict() for _ in range(period)]
    beau_bins = [dict() for _ in range(period)]

    for idx in range(N_CRIB):
        pt_val = CRIB_PT_NUM[idx]
        ct_val = ct_vals[idx]
        vig_k = (ct_val - pt_val) % MOD
        beau_k = (ct_val + pt_val) % MOD

        if model_a:
            res = CRIB_POS[idx] % period
        else:
            res = mapped_positions[idx] % period

        d = vig_bins[res]
        d[vig_k] = d.get(vig_k, 0) + 1
        d = beau_bins[res]
        d[beau_k] = d.get(beau_k, 0) + 1

    vig_score = sum(max(d.values()) if d else 0 for d in vig_bins)
    beau_score = sum(max(d.values()) if d else 0 for d in beau_bins)
    return vig_score, beau_score


def score_fast_p7_model_a(ct_vals):
    """Highly optimized Model A scoring at period 7 using precomputed groups."""
    vig_score = 0
    beau_score = 0

    for group in MODEL_A_GROUPS_P7:
        if not group:
            continue
        vk = {}
        bk = {}
        for idx in group:
            pt_val = CRIB_PT_NUM[idx]
            ct_val = ct_vals[idx]
            v = (ct_val - pt_val) % MOD
            b = (ct_val + pt_val) % MOD
            vk[v] = vk.get(v, 0) + 1
            bk[b] = bk.get(b, 0) + 1
        vig_score += max(vk.values())
        beau_score += max(bk.values())

    return vig_score, beau_score


def main():
    print("=" * 60)
    print("E-S-19: Double Columnar Transposition + Periodic Vig/Beau")
    print("=" * 60)
    print(f"Model A: CT = col2(col1(Vig(PT, key)))  [key at original pos]")
    print(f"Model B: CT = Vig(col2(col1(PT)), key)  [key at output pos]")
    print()

    ALL_PERIODS = [3, 4, 5, 6, 7, 8]
    EXPECTED_RANDOM = {3: 5.5, 4: 6.5, 5: 7.0, 6: 7.5, 7: 8.2, 8: 9.0}

    exhaustive_widths = [5, 6, 7]
    global_best = 0
    global_best_config = ""
    global_best_period = 0
    top_results = []  # (score, config_string, period)
    total_pairs = 0
    t0 = time.time()

    # Precompute all permutations for each width
    print("Precomputing permutations...")
    all_perms = {}
    for w in exhaustive_widths:
        all_perms[w] = precompute_all_perms(w)
        print(f"  Width {w}: {len(all_perms[w])} orderings precomputed")

    # Precompute crib index arrays
    crib_after = {}  # crib_after[w][perm_idx] = [perm_inv[CRIB_POS[k]] for k in range(N_CRIB)]
    for w in exhaustive_widths:
        crib_after[w] = []
        for order, perm, perm_inv in all_perms[w]:
            ca = [perm_inv[CRIB_POS[k]] for k in range(N_CRIB)]
            crib_after[w].append(ca)

    print("Precomputation done.\n")

    # Phase 1: Exhaustive width pairs, primary filter at period 7
    print("=" * 60)
    print("  Phase 1: Exhaustive (widths 5-7), period 7 filter")
    print("=" * 60)

    SIGNAL_CUTOFF = 12  # Store anything above this for re-check at other periods

    for w1 in exhaustive_widths:
        for w2 in exhaustive_widths:
            n1 = len(all_perms[w1])
            n2 = len(all_perms[w2])
            n_pairs = n1 * n2
            print(f"\n  Width ({w1},{w2}): {n1} × {n2} = {n_pairs:,} pairs")

            phase_best = 0
            phase_best_config = ""
            checked = 0
            phase_t0 = time.time()

            perms2_data = all_perms[w2]

            for i1 in range(n1):
                order1, perm1, perm1_inv = all_perms[w1][i1]
                ca1 = crib_after[w1][i1]  # perm1_inv at crib positions

                for i2 in range(n2):
                    order2, perm2, perm2_inv = perms2_data[i2]

                    # Compute mapped positions: combined_inv[j] = perm2_inv[perm1_inv[j]]
                    # For crib position k: mapped[k] = perm2_inv[ca1[k]]
                    mapped = [perm2_inv[ca1[k]] for k in range(N_CRIB)]
                    ct_vals = [CT_NUM[m] for m in mapped]

                    # Model A, period 7 (fast path)
                    a_vig, a_beau = score_fast_p7_model_a(ct_vals)

                    # Model B, period 7
                    b_vig, b_beau = score_at_period(ct_vals, mapped, 7, model_a=False)

                    best_here = max(a_vig, a_beau, b_vig, b_beau)

                    if best_here > phase_best:
                        phase_best = best_here
                        # Determine which variant
                        for label, s in [("A_vig", a_vig), ("A_beau", a_beau),
                                         ("B_vig", b_vig), ("B_beau", b_beau)]:
                            if s == best_here:
                                phase_best_config = f"w=({w1},{w2}) o1={order1} o2={order2} {label} p=7"
                                break

                    if best_here > global_best:
                        global_best = best_here
                        global_best_config = phase_best_config
                        global_best_period = 7
                        if best_here >= SIGNAL_THRESHOLD:
                            print(f"  *** SIGNAL: {best_here}/24 — {global_best_config}")

                    # Store interesting results for multi-period re-check
                    if best_here >= SIGNAL_CUTOFF:
                        for label, s in [("A_vig", a_vig), ("A_beau", a_beau),
                                         ("B_vig", b_vig), ("B_beau", b_beau)]:
                            if s >= SIGNAL_CUTOFF:
                                top_results.append((s, f"w=({w1},{w2}) o1={order1} o2={order2} {label} p=7", 7))

                    checked += 1
                    total_pairs += 1

                # Progress every 100 outer iterations for large searches
                if (i1 + 1) % max(1, n1 // 20) == 0:
                    elapsed = time.time() - phase_t0
                    rate = checked / elapsed if elapsed > 0 else 0
                    pct = 100.0 * checked / n_pairs
                    print(f"    [{checked:>10,}/{n_pairs:,}] {pct:5.1f}%  best={phase_best}/24  ({elapsed:.0f}s, {rate:.0f}/s)", flush=True)

            elapsed = time.time() - phase_t0
            print(f"  Width ({w1},{w2}): best={phase_best}/24  exp_random=8.2  ({elapsed:.1f}s)")

    phase1_time = time.time() - t0

    # Phase 2: Re-check top candidates at all periods
    print("\n" + "=" * 60)
    print(f"  Phase 2: Multi-period re-check ({len(top_results)} candidates)")
    print("=" * 60)

    # Deduplicate and keep top 1000
    top_results.sort(key=lambda x: -x[0])
    seen = set()
    unique_top = []
    for score, config, p in top_results:
        # Extract the ordering info (unique by orders, not by label)
        key = config.split(" B_")[0].split(" A_")[0]
        if key not in seen:
            seen.add(key)
            unique_top.append((score, config, p))
        if len(unique_top) >= 1000:
            break

    print(f"  Unique configs to re-check: {len(unique_top)}")

    recheck_results = []
    for score_p7, config, _ in unique_top[:200]:
        # Parse config to reconstruct the permutation
        # This is a bit hacky but works for the format we used
        parts = config.split()
        w_str = parts[0]  # w=(X,Y)
        w1 = int(w_str.split("(")[1].split(",")[0])
        w2 = int(w_str.split(",")[1].split(")")[0])

        o1_start = config.index("o1=") + 3
        o1_end = config.index(" o2=")
        o1_str = config[o1_start:o1_end]
        o1 = eval(o1_str)

        o2_start = config.index("o2=") + 3
        o2_end_candidates = [config.index(" A_") if " A_" in config else len(config),
                             config.index(" B_") if " B_" in config else len(config)]
        o2_end = min(o2_end_candidates)
        o2_str = config[o2_start:o2_end]
        o2 = eval(o2_str)

        perm1 = columnar_encrypt_perm(CT_LEN, w1, list(o1))
        perm1_inv = invert_perm(perm1)
        perm2 = columnar_encrypt_perm(CT_LEN, w2, list(o2))
        perm2_inv = invert_perm(perm2)

        mapped = [perm2_inv[perm1_inv[CRIB_POS[k]]] for k in range(N_CRIB)]
        ct_vals = [CT_NUM[m] for m in mapped]

        for p in ALL_PERIODS:
            a_vig, a_beau = score_at_period(ct_vals, mapped, p, model_a=True)
            b_vig, b_beau = score_at_period(ct_vals, mapped, p, model_a=False)

            for label, s in [("A_vig", a_vig), ("A_beau", a_beau),
                             ("B_vig", b_vig), ("B_beau", b_beau)]:
                if s > global_best:
                    global_best = s
                    global_best_config = f"w=({w1},{w2}) o1={list(o1)} o2={list(o2)} {label} p={p}"
                    global_best_period = p
                    if s >= SIGNAL_THRESHOLD:
                        print(f"  *** SIGNAL: {s}/24 — {global_best_config}")

                recheck_results.append({
                    "score": s, "period": p, "model": label,
                    "w1": w1, "w2": w2, "o1": list(o1), "o2": list(o2),
                    "score_p7": score_p7,
                })

    if recheck_results:
        recheck_results.sort(key=lambda x: -x["score"])
        print(f"  Re-check best: {recheck_results[0]['score']}/24 at p={recheck_results[0]['period']}")

    # Phase 3: Also test some identity + single columnar combos as sanity check
    # (col2 = identity means just single columnar, which we know is noise)
    print("\n  Sanity check: single columnar (second = identity)")
    for w in exhaustive_widths:
        best_single = 0
        for order, perm, perm_inv in all_perms[w]:
            # Only first columnar, second is identity
            mapped = [perm_inv[CRIB_POS[k]] for k in range(N_CRIB)]
            ct_vals = [CT_NUM[m] for m in mapped]
            a_vig, a_beau = score_fast_p7_model_a(ct_vals)
            best_single = max(best_single, a_vig, a_beau)
        print(f"    Single columnar w={w}: best={best_single}/24 at p=7 (expected noise ~8.2)")

    # Summary
    elapsed_total = time.time() - t0

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Time: {elapsed_total:.0f}s ({elapsed_total/60:.1f} min)")
    print(f"  Total pairs tested: {total_pairs:,}")
    print(f"  Phase 1 (p=7 filter): {phase1_time:.0f}s")
    print(f"  Global best: {global_best}/24 at p={global_best_period}")
    if global_best_config:
        print(f"  Config: {global_best_config}")

    exp = EXPECTED_RANDOM.get(global_best_period, 8.0)
    print(f"  Expected random at p={global_best_period}: ~{exp}")
    excess = global_best - exp
    print(f"  Excess over random: {excess:.1f}")

    # Verdict
    if global_best >= SIGNAL_THRESHOLD:
        verdict = "SIGNAL"
    elif global_best >= 14 and global_best_period <= 7:
        verdict = "INVESTIGATE"
    else:
        verdict = "NOISE"

    print(f"  VERDICT: {verdict}")

    # Top 10
    all_final = top_results + [(r["score"], f"w=({r['w1']},{r['w2']}) {r['model']} p={r['period']}", r["period"])
                                for r in recheck_results]
    all_final.sort(key=lambda x: -x[0])
    print(f"\n  Top 10 results:")
    seen_configs = set()
    shown = 0
    for score, config, p in all_final:
        key = f"{score}_{config}"
        if key in seen_configs:
            continue
        seen_configs.add(key)
        exp_r = EXPECTED_RANDOM.get(p, 8.0)
        print(f"    {score}/24 (exp={exp_r:.1f})  {config}")
        shown += 1
        if shown >= 10:
            break

    # Save results
    output = {
        "experiment": "E-S-19",
        "description": "Double columnar transposition + periodic Vigenere/Beaufort",
        "total_pairs": total_pairs,
        "elapsed_seconds": elapsed_total,
        "global_best_score": global_best,
        "global_best_config": global_best_config,
        "global_best_period": global_best_period,
        "verdict": verdict,
        "expected_random": EXPECTED_RANDOM,
        "top_results": [{"score": s, "config": c, "period": p}
                        for s, c, p in all_final[:50]],
    }

    with open("results/e_s_19_double_columnar.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Artifacts: results/e_s_19_double_columnar.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_19_double_columnar.py")
    print(f"\nRESULT: best={global_best}/24 verdict={verdict}")


if __name__ == "__main__":
    main()
