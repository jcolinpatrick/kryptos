#!/usr/bin/env python3
"""E-FRAC-11: Testing the Validity of the Bimodal Fingerprint.

The bimodal fingerprint is a HYPOTHESIS, not a proven fact. It claims:
- Positions 22-30 (ENE) are approximately preserved by the transposition
- Positions 64-74 (BC) are scrambled by the transposition

This experiment tests whether the bimodal assumption is justified:

1. Under the IDENTITY permutation + periodic substitution, do ENE cribs
   match better than BC cribs? (If yes, bimodal might just reflect the
   substitution cipher's behavior, not a transposition)

2. For high-scoring random permutations (no bimodal filter), do they tend
   to preserve ENE more than BC? (If yes, bimodal emerges from data)

3. For high-scoring structured permutations (columnar widths 5-15), do
   the best ones preserve ENE more than BC? (Pattern check)

4. Compare scoring WITH vs WITHOUT bimodal pre-filter

5. Alternative hypothesis: what if BC cribs are WRONG (off by 1-2 positions)?
   If BC cribs have indexing errors, the "bimodal" pattern would be an artifact.
"""
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
random.seed(42)

# Separate crib positions into ENE and BC regions
ENE_POSITIONS = sorted([p for p in CRIB_SET if 21 <= p <= 33])
BC_POSITIONS = sorted([p for p in CRIB_SET if 63 <= p <= 73])
OTHER_POSITIONS = sorted([p for p in CRIB_SET if p not in ENE_POSITIONS and p not in BC_POSITIONS])

print(f"ENE positions: {ENE_POSITIONS}")
print(f"BC positions: {BC_POSITIONS}")
print(f"Other positions: {OTHER_POSITIONS}")


def bimodal_check(perm, ene_tolerance=5, bc_max_identity=4):
    for i in range(22, 31):
        if i < CT_LEN:
            if abs(perm[i] - i) > ene_tolerance:
                return False
    bc_identity = 0
    for i in range(64, min(75, CT_LEN)):
        if abs(perm[i] - i) <= 2:
            bc_identity += 1
    return bc_identity <= bc_max_identity


def score_periodic(perm, period, variant="vigenere"):
    """Score perm under periodic substitution, returning per-position matches."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i

    residue_keys = {}
    per_position = {}

    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]

        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD

        residue = ct_pos % period  # Model B (trans then sub)

        if residue not in residue_keys:
            residue_keys[residue] = k
            per_position[pt_pos] = True
        elif residue_keys[residue] == k:
            per_position[pt_pos] = True
        else:
            per_position[pt_pos] = False

    total = sum(1 for v in per_position.values() if v)
    return total, per_position


def score_best(perm, periods=(2, 3, 4, 5, 6, 7),
               variants=("vigenere", "beaufort", "variant_beaufort")):
    """Return best score across all configs, plus per-position detail at best."""
    best_score = 0
    best_detail = None
    best_cfg = None

    for period in periods:
        for variant in variants:
            score, detail = score_periodic(perm, period, variant)
            if score > best_score:
                best_score = score
                best_detail = detail
                best_cfg = (period, variant)

    return best_score, best_detail, best_cfg


def region_match_rate(detail, positions):
    """Compute match rate for a set of crib positions."""
    matches = sum(1 for p in positions if detail.get(p, False))
    return matches / max(len(positions), 1)


def main():
    t0 = time.time()
    print()
    print("=" * 70)
    print("E-FRAC-11: Testing the Validity of the Bimodal Fingerprint")
    print("=" * 70)
    print()

    # ── Part 1: Identity permutation baseline ────────────────────────
    print("Part 1: Identity Permutation (No Transposition)")
    print("-" * 50)

    identity = list(range(CT_LEN))
    for period in [3, 4, 5, 6, 7]:
        for variant in ["vigenere", "beaufort", "variant_beaufort"]:
            score, detail = score_periodic(identity, period, variant)
            ene_rate = region_match_rate(detail, ENE_POSITIONS)
            bc_rate = region_match_rate(detail, BC_POSITIONS)
            if score >= 6:
                print(f"  p={period}, {variant[:4]}: score={score}/24, "
                      f"ENE={ene_rate:.2f}, BC={bc_rate:.2f}")

    # Best at identity
    best_id_score, best_id_detail, best_id_cfg = score_best(identity)
    ene_rate = region_match_rate(best_id_detail, ENE_POSITIONS)
    bc_rate = region_match_rate(best_id_detail, BC_POSITIONS)
    print(f"\n  BEST identity: score={best_id_score}/24 at {best_id_cfg}")
    print(f"  ENE match rate: {ene_rate:.2f} ({sum(1 for p in ENE_POSITIONS if best_id_detail.get(p, False))}/{len(ENE_POSITIONS)})")
    print(f"  BC match rate:  {bc_rate:.2f} ({sum(1 for p in BC_POSITIONS if best_id_detail.get(p, False))}/{len(BC_POSITIONS)})")
    print(f"  If ENE >> BC under identity, bimodal may just reflect cipher behavior")

    # ── Part 2: Random permutations — do best ones show bimodal? ─────
    print()
    print("Part 2: Random Permutations — Does Bimodal Emerge from Data?")
    print("-" * 50)

    N_RANDOM = 500_000
    score_ene_bc = []  # (score, ene_rate, bc_rate, is_bimodal)

    score_dist_all = Counter()
    score_dist_bimodal = Counter()
    ene_vs_bc_at_high_scores = defaultdict(list)

    for trial in range(N_RANDOM):
        perm = list(range(CT_LEN))
        random.shuffle(perm)

        score, detail, cfg = score_best(perm)
        is_bimodal = bimodal_check(perm)

        score_dist_all[score] += 1
        if is_bimodal:
            score_dist_bimodal[score] += 1

        if score >= 8:
            ene_rate = region_match_rate(detail, ENE_POSITIONS)
            bc_rate = region_match_rate(detail, BC_POSITIONS)
            ene_vs_bc_at_high_scores[score].append({
                "ene": ene_rate,
                "bc": bc_rate,
                "bimodal": is_bimodal,
            })

        if (trial + 1) % 100000 == 0:
            print(f"  [{trial+1:,}] bimodal_count={sum(score_dist_bimodal.values())}")

    print(f"\n  Score distribution (all {N_RANDOM:,} random perms):")
    for s in sorted(score_dist_all.keys(), reverse=True):
        if score_dist_all[s] > 0:
            bm = score_dist_bimodal.get(s, 0)
            print(f"    score={s:2d}: {score_dist_all[s]:,} total, "
                  f"{bm:,} bimodal ({100*bm/max(score_dist_all[s],1):.1f}%)")

    print(f"\n  ENE vs BC match rates at high scores:")
    for s in sorted(ene_vs_bc_at_high_scores.keys(), reverse=True):
        entries = ene_vs_bc_at_high_scores[s]
        if entries:
            avg_ene = sum(e["ene"] for e in entries) / len(entries)
            avg_bc = sum(e["bc"] for e in entries) / len(entries)
            n_bimodal = sum(1 for e in entries if e["bimodal"])
            print(f"    score={s:2d}: N={len(entries):,}, "
                  f"avg_ENE={avg_ene:.3f}, avg_BC={avg_bc:.3f}, "
                  f"ENE>BC={sum(1 for e in entries if e['ene']>e['bc'])}, "
                  f"bimodal={n_bimodal}")

    # ── Part 3: Does dropping bimodal find better columnar results? ──
    print()
    print("Part 3: Width-9 Columnar WITHOUT Bimodal Filter")
    print("-" * 50)
    print("Testing all 362,880 orderings without bimodal pre-filter...")

    import itertools

    WIDTH = 9
    N_ROWS = CT_LEN // WIDTH
    REMAINDER = CT_LEN % WIDTH
    COL_HEIGHTS = [N_ROWS + 1 if j < REMAINDER else N_ROWS for j in range(WIDTH)]

    def build_columnar_perm(order):
        perm = []
        for c in range(WIDTH):
            col = order[c]
            height = COL_HEIGHTS[col]
            for row in range(height):
                perm.append(row * WIDTH + col)
        return perm

    w9_score_dist = Counter()
    w9_top = []
    n_tested_w9 = 0

    for order in itertools.permutations(range(WIDTH)):
        perm = build_columnar_perm(order)
        score, detail, cfg = score_best(perm)
        w9_score_dist[score] += 1
        n_tested_w9 += 1

        if score >= 10:
            ene_rate = region_match_rate(detail, ENE_POSITIONS)
            bc_rate = region_match_rate(detail, BC_POSITIONS)
            w9_top.append({
                "order": list(order),
                "score": score,
                "config": cfg,
                "ene_rate": ene_rate,
                "bc_rate": bc_rate,
                "bimodal": bimodal_check(perm),
            })

    print(f"  Tested: {n_tested_w9:,} orderings (no bimodal filter)")
    print(f"  Score distribution:")
    for s in sorted(w9_score_dist.keys(), reverse=True):
        if w9_score_dist[s] > 0:
            print(f"    score={s:2d}: {w9_score_dist[s]:,}")

    if w9_top:
        w9_top.sort(key=lambda x: -x["score"])
        print(f"\n  Top results (score >= 10):")
        for r in w9_top[:10]:
            bm_str = "bimodal" if r["bimodal"] else "NOT-bimodal"
            print(f"    score={r['score']}, order={r['order']}, "
                  f"cfg={r['config']}, ENE={r['ene_rate']:.2f}, "
                  f"BC={r['bc_rate']:.2f}, {bm_str}")

    # ── Part 4: Crib position sensitivity analysis ───────────────────
    print()
    print("Part 4: Per-Position Crib Match Rates (Identity + Random)")
    print("-" * 50)

    # Under identity permutation, at various periods, which cribs match most?
    print("  Under identity, best config:")
    for pt_pos in sorted(CRIB_SET):
        matched = best_id_detail.get(pt_pos, False)
        region = "ENE" if pt_pos in ENE_POSITIONS else ("BC" if pt_pos in BC_POSITIONS else "OTHER")
        status = "MATCH" if matched else "miss"
        print(f"    pos={pt_pos:2d} ({region:5s}): {status}  "
              f"PT={CRIB_DICT[pt_pos]} CT={CT[pt_pos]}")

    # Under random permutations, match frequency per position
    print("\n  Per-position match frequency (random perms, N=50,000):")
    pos_match_counts = Counter()
    N_POS_TEST = 50000
    random.seed(99)

    for _ in range(N_POS_TEST):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        _, detail, _ = score_best(perm)
        for p, matched in detail.items():
            if matched:
                pos_match_counts[p] += 1

    print(f"  {'Pos':>4s}  {'Region':>6s}  {'Match%':>8s}  {'PT':>3s}  {'CT':>3s}")
    for pt_pos in sorted(CRIB_SET):
        region = "ENE" if pt_pos in ENE_POSITIONS else ("BC" if pt_pos in BC_POSITIONS else "OTHER")
        pct = 100 * pos_match_counts[pt_pos] / N_POS_TEST
        print(f"  {pt_pos:4d}  {region:>6s}  {pct:8.2f}%  {CRIB_DICT[pt_pos]:>3s}  {CT[pt_pos]:>3s}")

    ene_avg = sum(pos_match_counts[p] for p in ENE_POSITIONS) / len(ENE_POSITIONS) / N_POS_TEST
    bc_avg = sum(pos_match_counts[p] for p in BC_POSITIONS) / len(BC_POSITIONS) / N_POS_TEST
    print(f"\n  Average match rate (random perms):")
    print(f"    ENE: {100*ene_avg:.2f}%")
    print(f"    BC:  {100*bc_avg:.2f}%")
    print(f"    Ratio ENE/BC: {ene_avg/bc_avg:.2f}" if bc_avg > 0 else "    BC rate is 0")

    # ── Part 5: Shifted crib test ────────────────────────────────────
    print()
    print("Part 5: What If BC Cribs Are Off by ±1?")
    print("-" * 50)

    for shift in [-2, -1, 0, 1, 2]:
        # Create shifted BC crib dict
        shifted_crib = dict(CRIB_DICT)
        bc_text = "BERLINCLOCK"
        # Remove original BC positions
        for p in BC_POSITIONS:
            if p in shifted_crib:
                del shifted_crib[p]
        # Add shifted BC positions
        for i, ch in enumerate(bc_text):
            new_pos = 63 + i + shift
            if 0 <= new_pos < CT_LEN:
                shifted_crib[new_pos] = ch

        shifted_crib_num = {pos: ALPH_IDX[ch] for pos, ch in shifted_crib.items()}
        shifted_crib_set = set(shifted_crib.keys())

        # Score identity with shifted cribs
        def score_shifted(perm, period, variant):
            inv = [0] * len(perm)
            for i, p in enumerate(perm):
                inv[p] = i
            residue_keys = {}
            matches = 0
            for pt_pos in sorted(shifted_crib_set):
                ct_pos = inv[pt_pos]
                ct_val = CT_NUM[ct_pos]
                pt_val = shifted_crib_num[pt_pos]
                if variant == "vigenere":
                    k = (ct_val - pt_val) % MOD
                elif variant == "beaufort":
                    k = (ct_val + pt_val) % MOD
                else:
                    k = (pt_val - ct_val) % MOD
                residue = ct_pos % period
                if residue not in residue_keys:
                    residue_keys[residue] = k
                    matches += 1
                elif residue_keys[residue] == k:
                    matches += 1
            return matches

        # Test identity permutation
        best = 0
        best_cfg = None
        for period in [3, 4, 5, 6, 7]:
            for variant in ["vigenere", "beaufort", "variant_beaufort"]:
                s = score_shifted(identity, period, variant)
                if s > best:
                    best = s
                    best_cfg = (period, variant)

        print(f"  BC shift={shift:+d}: best identity score = {best}/24 at {best_cfg}")

    # ── Summary ──────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print("=" * 70)
    print("SUMMARY & CONCLUSIONS")
    print("=" * 70)

    print(f"\n1. IDENTITY (no transposition):")
    print(f"   Best score: {best_id_score}/24")
    ene_r = region_match_rate(best_id_detail, ENE_POSITIONS)
    bc_r = region_match_rate(best_id_detail, BC_POSITIONS)
    print(f"   ENE match rate: {ene_r:.2f}, BC match rate: {bc_r:.2f}")
    if ene_r > bc_r:
        print(f"   → ENE matches better than BC even at identity (no transposition)")
        print(f"   → This means 'bimodal' could be a property of the CIPHER, not transposition")
    else:
        print(f"   → ENE and BC match similarly under identity")

    print(f"\n2. RANDOM PERMUTATIONS:")
    total_bimodal = sum(score_dist_bimodal.values())
    print(f"   Bimodal-passing: {total_bimodal}/{N_RANDOM} = {100*total_bimodal/N_RANDOM:.4f}%")
    print(f"   Best score (all): {max(score_dist_all.keys())}/24")
    if score_dist_bimodal:
        print(f"   Best score (bimodal only): {max(score_dist_bimodal.keys())}/24")
    else:
        print(f"   Best score (bimodal only): N/A (no bimodal-passing perms)")

    print(f"\n3. WIDTH-9 COLUMNAR (no bimodal filter):")
    print(f"   Best score: {max(w9_score_dist.keys())}/24")
    if w9_top:
        print(f"   Top result: {w9_top[0]}")

    print(f"\n4. BIMODAL FINGERPRINT VALIDITY:")
    print(f"   Is ENE > BC inherent? {ene_r > bc_r}")
    print(f"   Does bimodal emerge in high-scoring random perms? "
          f"(check Part 2 analysis above)")

    print(f"\nTotal time: {elapsed:.1f}s")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-11",
        "description": "Testing the validity of the bimodal fingerprint hypothesis",
        "identity_best_score": best_id_score,
        "identity_best_config": str(best_id_cfg),
        "identity_ene_rate": round(ene_r, 3),
        "identity_bc_rate": round(bc_r, 3),
        "random_score_dist": {str(k): v for k, v in score_dist_all.items()},
        "random_bimodal_score_dist": {str(k): v for k, v in score_dist_bimodal.items()},
        "w9_score_dist": {str(k): v for k, v in w9_score_dist.items()},
        "w9_top": w9_top[:20],
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_11_bimodal_validity.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
