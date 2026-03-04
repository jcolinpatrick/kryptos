#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""E-S-133: Width-9 Columnar Transposition as Multi-Layer Component.

Tests all 362,880 width-9 column orderings as the transposition layer
in a two-layer cipher model (substitution + transposition).

Motivated by:
  - Sanborn's "10.8 rows" annotation (97/9 = 10.78 ≈ 10.8)
  - DFT peak at k=9 (period ~10.8) from E-S-25
  - Width-9 is RELATIVELY UNTESTED as a multi-layer transposition

Models:
  Model B (trans->sub, matches K3): CT[i] = sub(PT[perm[i]])
  Model A (sub->trans): CT[i] = sub_at_perm[i](PT[perm[i]])

Variants: Vigenere, Beaufort, Variant Beaufort
Periods tested: 2-14

attack(ciphertext, **params) -> list[tuple[float, str, str]]
    Standard attack interface.
    params: width (int, default 9), periods (list[int], default 2-14),
            threshold (int, default 10)
"""
import itertools
import json
import os
import time
from collections import defaultdict

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD

# -- Precompute CT and crib numeric values --

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())  # positions where PT is known
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


def _build_col_heights(width, ct_len):
    n_rows_full = ct_len // width
    remainder = ct_len % width
    return [n_rows_full + 1 if j < remainder else n_rows_full for j in range(width)]


WIDTH = 9
COL_HEIGHTS = _build_col_heights(WIDTH, CT_LEN)


def build_columnar_perm(order, width=None, col_heights=None):
    """Build the gather permutation for columnar transposition encryption.

    Encryption: write PT row-by-row into grid, read columns in `order`.
    output[i] = input[perm[i]] (gather convention).
    """
    if width is None:
        width = WIDTH
    if col_heights is None:
        col_heights = COL_HEIGHTS
    perm = []
    for c in range(width):
        col = order[c]
        height = col_heights[col]
        for row in range(height):
            perm.append(row * width + col)
    return perm


def check_periodic_consistency_model_b(perm, period, variant, ct_num=None):
    """Model B: trans then sub. CT[i] = variant(PT[perm[i]], key[i]).

    For periodic key: key[i] = key[i % period].
    Derive key[i] at positions where perm[i] is a crib position.
    Check if all key values in same residue class agree.

    Returns (n_consistent, n_constrained) where:
      n_consistent = number of crib-derived key values consistent with periodicity
      n_constrained = total number of crib-reachable positions
    """
    if ct_num is None:
        ct_num = CT_NUM
    # Collect key values grouped by residue class
    residue_groups = defaultdict(list)  # residue -> [(i, key_val)]

    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = ct_num[i]
            if variant == 0:    # Vigenere: key = (CT - PT) % 26
                k = (ct_val - pt_val) % MOD
            elif variant == 1:  # Beaufort: key = (CT + PT) % 26
                k = (ct_val + pt_val) % MOD
            else:               # Variant Beaufort: key = (PT - CT) % 26
                k = (pt_val - ct_val) % MOD
            residue_groups[i % period].append(k)

    # Check consistency within each group
    n_consistent = 0
    n_constrained = 0
    for residue, vals in residue_groups.items():
        n_constrained += len(vals)
        # All values in this group must be identical for periodicity
        if len(set(vals)) == 1:
            n_consistent += len(vals)
        else:
            # Count the majority value as "consistent", rest as inconsistent
            from collections import Counter
            counts = Counter(vals)
            majority = counts.most_common(1)[0][1]
            n_consistent += majority

    return n_consistent, n_constrained


def check_periodic_consistency_model_a(perm, period, variant, ct_num=None):
    """Model A: sub then trans. CT[i] = inter[perm[i]] where inter[j] = variant(PT[j], key[j]).

    So: key[perm[i]] = variant_inv(CT[i], PT[perm[i]]).
    For periodic key: key[perm[i]] = key[perm[i] % period].
    Group by (perm[i] % period) and check consistency.
    """
    if ct_num is None:
        ct_num = CT_NUM
    residue_groups = defaultdict(list)

    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = ct_num[i]
            if variant == 0:    # Vigenere
                k = (ct_val - pt_val) % MOD
            elif variant == 1:  # Beaufort
                k = (ct_val + pt_val) % MOD
            else:               # Variant Beaufort
                k = (pt_val - ct_val) % MOD
            residue_groups[src % period].append(k)

    n_consistent = 0
    n_constrained = 0
    for residue, vals in residue_groups.items():
        n_constrained += len(vals)
        if len(set(vals)) == 1:
            n_consistent += len(vals)
        else:
            from collections import Counter
            counts = Counter(vals)
            majority = counts.most_common(1)[0][1]
            n_consistent += majority

    return n_consistent, n_constrained


def count_crib_reachable(perm):
    """Count how many CT positions map to known crib positions."""
    return sum(1 for src in perm if src in CRIB_SET)


# -- Standard attack interface --

VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]
MODEL_NAMES = ["A_sub_trans", "B_trans_sub"]


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    width = params.get("width", WIDTH)
    periods = params.get("periods", list(range(2, 15)))
    threshold = params.get("threshold", 10)

    ct_len = len(ciphertext)
    ct_num = [ALPH_IDX[c] for c in ciphertext]
    col_heights = _build_col_heights(width, ct_len)

    results = []

    for order in itertools.permutations(range(width)):
        perm = build_columnar_perm(order, width=width, col_heights=col_heights)

        for model in range(2):  # 0=A, 1=B
            for variant in range(3):  # 0=vig, 1=beau, 2=vb
                for period in periods:
                    if model == 0:
                        n_con, n_tot = check_periodic_consistency_model_a(
                            perm, period, variant, ct_num=ct_num)
                    else:
                        n_con, n_tot = check_periodic_consistency_model_b(
                            perm, period, variant, ct_num=ct_num)

                    if n_con >= threshold:
                        desc = (f"width{width}_columnar "
                                f"order={list(order)} "
                                f"model={MODEL_NAMES[model]} "
                                f"variant={VARIANT_NAMES[variant]} "
                                f"period={period} "
                                f"consistent={n_con}/{n_tot}")
                        results.append((float(n_con), "", desc))

    results.sort(key=lambda x: -x[0])
    return results


# -- Main sweep --

def main():
    t0 = time.time()

    n_rows_full = CT_LEN // WIDTH
    remainder = CT_LEN % WIDTH
    print(f"Width-9 grid: {WIDTH} columns")
    print(f"  Full rows: {n_rows_full}, remainder: {remainder}")
    print(f"  Column heights: {COL_HEIGHTS}")
    print(f"  Verify: {sum(COL_HEIGHTS)} = {CT_LEN}")
    print()

    print("=" * 70)
    print("E-S-133: Width-9 Columnar Transposition -- Multi-Layer Test")
    print("=" * 70)
    print(f"Orderings to test: {WIDTH}! = 362,880")
    print(f"Periods: 2-14 (13 periods)")
    print(f"Variants: Vigenere(0), Beaufort(1), Variant Beaufort(2)")
    print(f"Models: A (sub->trans), B (trans->sub)")
    print(f"Total checks: 362,880 x 13 x 3 x 2 = {362880 * 13 * 3 * 2:,}")
    print()

    PERIODS = list(range(2, 15))

    # Track best results
    best_overall = {"score": 0}
    best_by_period = {p: {"score": 0} for p in PERIODS}
    best_by_variant = {v: {"score": 0} for v in range(3)}
    best_by_model = {m: {"score": 0} for m in range(2)}

    # Track perfect matches (all constrained positions consistent)
    perfect_matches = []

    # Distribution tracking
    score_dist = defaultdict(int)  # score -> count

    # For comparison: track how many orderings achieve each score threshold
    threshold_counts = {t: 0 for t in [18, 20, 22, 24]}

    n_tested = 0
    n_orderings = 0
    last_report = t0

    for order in itertools.permutations(range(WIDTH)):
        n_orderings += 1
        perm = build_columnar_perm(order)
        n_reachable = count_crib_reachable(perm)

        for model in range(2):  # 0=A, 1=B
            for variant in range(3):  # 0=vig, 1=beau, 2=vb
                for period in PERIODS:
                    n_tested += 1

                    if model == 0:
                        n_con, n_tot = check_periodic_consistency_model_a(
                            perm, period, variant)
                    else:
                        n_con, n_tot = check_periodic_consistency_model_b(
                            perm, period, variant)

                    score_dist[n_con] += 1

                    if n_con > best_overall["score"]:
                        best_overall = {
                            "score": n_con,
                            "constrained": n_tot,
                            "reachable": n_reachable,
                            "order": list(order),
                            "model": MODEL_NAMES[model],
                            "variant": VARIANT_NAMES[variant],
                            "period": period,
                        }

                    if n_con > best_by_period[period]["score"]:
                        best_by_period[period] = {
                            "score": n_con,
                            "order": list(order),
                            "model": MODEL_NAMES[model],
                            "variant": VARIANT_NAMES[variant],
                        }

                    if n_con > best_by_variant[variant]["score"]:
                        best_by_variant[variant] = {
                            "score": n_con,
                            "order": list(order),
                            "model": MODEL_NAMES[model],
                            "period": period,
                        }

                    if n_con > best_by_model[model]["score"]:
                        best_by_model[model] = {
                            "score": n_con,
                            "order": list(order),
                            "variant": VARIANT_NAMES[variant],
                            "period": period,
                        }

                    # Track thresholds
                    for t in threshold_counts:
                        if n_con >= t:
                            threshold_counts[t] += 1

                    # Track perfect matches
                    if n_con == n_tot and n_tot >= 20:
                        perfect_matches.append({
                            "score": n_con,
                            "constrained": n_tot,
                            "order": list(order),
                            "model": MODEL_NAMES[model],
                            "variant": VARIANT_NAMES[variant],
                            "period": period,
                        })

        # Progress report every 30 seconds
        now = time.time()
        if now - last_report > 30:
            elapsed = now - t0
            rate = n_orderings / elapsed
            pct = 100 * n_orderings / 362880
            eta = (362880 - n_orderings) / rate if rate > 0 else 0
            print(f"  [{pct:5.1f}%] {n_orderings:,}/{362880:,} orderings, "
                  f"best={best_overall['score']}/24, "
                  f"rate={rate:.0f}/s, ETA={eta:.0f}s")
            last_report = now

    elapsed = time.time() - t0

    # -- Results --
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total orderings: {n_orderings:,}")
    print(f"Total checks: {n_tested:,}")
    print(f"Time: {elapsed:.1f}s ({n_tested/elapsed:.0f} checks/s)")
    print()

    print("BEST OVERALL:")
    for k, v in best_overall.items():
        print(f"  {k}: {v}")
    print()

    print("BEST BY PERIOD:")
    for p in PERIODS:
        bp = best_by_period[p]
        print(f"  p={p:2d}: {bp['score']}/24  {bp.get('variant','?'):15s} "
              f"{bp.get('model','?'):15s} order={bp.get('order','?')}")
    print()

    print("BEST BY VARIANT:")
    for v in range(3):
        bv = best_by_variant[v]
        print(f"  {VARIANT_NAMES[v]:20s}: {bv['score']}/24  "
              f"p={bv.get('period','?')} {bv.get('model','?')}")
    print()

    print("BEST BY MODEL:")
    for m in range(2):
        bm = best_by_model[m]
        print(f"  {MODEL_NAMES[m]:15s}: {bm['score']}/24  "
              f"p={bm.get('period','?')} {bm.get('variant','?')}")
    print()

    print("THRESHOLD COUNTS:")
    for t, count in sorted(threshold_counts.items()):
        pct = 100 * count / n_tested if n_tested > 0 else 0
        print(f"  >= {t}/24: {count:,} ({pct:.4f}%)")
    print()

    print("PERFECT MATCHES (all constrained positions consistent, n>=20):")
    if perfect_matches:
        for pm in perfect_matches[:20]:
            print(f"  {pm['score']}/{pm['constrained']} "
                  f"p={pm['period']} {pm['variant']:15s} {pm['model']:15s} "
                  f"order={pm['order']}")
    else:
        print("  NONE")
    print()

    print("SCORE DISTRIBUTION (top 15):")
    for score_val, count in sorted(score_dist.items(), key=lambda x: -x[0])[:15]:
        pct = 100 * count / n_tested
        print(f"  {score_val:3d}/24: {count:>10,} ({pct:6.3f}%)")
    print()

    # -- Comparison with width-7 baseline --
    print("-" * 70)
    print("WIDTH-9 vs WIDTH-7 COMPARISON")
    print("-" * 70)
    print(f"Width-9 best: {best_overall['score']}/24")
    print(f"Width-7 best (E-S-62/91/94): 0/24 (all eliminated)")
    print(f"Width-7 noise floor: ~8.2/24 expected random at period 7")
    print()

    # Expected random baseline for width-9
    print("EXPECTED RANDOM BASELINES (approximate):")
    for p in [2, 3, 5, 7, 9, 11, 13]:
        print(f"  p={p:2d}: see score distribution above")
    print()

    # -- Verdict --
    print("=" * 70)
    NOISE = 8  # approximate noise floor for period <= 7
    if best_overall["score"] >= 18:
        verdict = "SIGNAL -- investigate further"
    elif best_overall["score"] > NOISE:
        verdict = "STORE -- above noise but not definitive"
    else:
        verdict = "NOISE -- width-9 columnar does not produce signal"
    print(f"VERDICT: {verdict}")
    print(f"Best score: {best_overall['score']}/24")
    print("=" * 70)

    # -- Save artifacts --
    os.makedirs("artifacts", exist_ok=True)
    artifact = {
        "experiment": "E-S-133",
        "description": "Width-9 columnar transposition as multi-layer component",
        "width": WIDTH,
        "n_orderings": n_orderings,
        "n_checks": n_tested,
        "periods": PERIODS,
        "best_overall": best_overall,
        "best_by_period": {str(k): v for k, v in best_by_period.items()},
        "threshold_counts": threshold_counts,
        "perfect_matches": perfect_matches[:50],
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
    }
    path = "artifacts/e_s_133_width9.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nResults saved to {path}")


if __name__ == "__main__":
    main()
