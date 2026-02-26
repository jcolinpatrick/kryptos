#!/usr/bin/env python3
"""E-OPGOLD-03: British Intelligence / MI6 / Five Eyes Keywords

K2 describes Operation Gold, a joint CIA/MI6 operation. A seasoned CIA
agent would recognize the MI6 connection and think of British intelligence
terminology. This experiment tests British intel, crypto history,
Operation Gold, and NATO phonetic keywords as Vigenere/Beaufort/Variant
Beaufort keys, both with identity transposition and with columnar
transposition at Bean-compatible widths {8, 13, 16}.

For width 8: all 8!=40320 column orderings.
For widths 13 and 16: identity + reversed + 1000 random orderings.

Output: results/e_opgold_03_british.json
"""
import itertools
import json
import os
import random
import sys
import time
from collections import defaultdict

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm,
)

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN

# ── Keywords ─────────────────────────────────────────────────────────────

KEYWORDS = {
    # Group 1 - British Intelligence
    "british": [
        "GCHQ", "FIVEYES", "MI", "SIS",
        "SECRETINTELLIGENCESERVICE", "CHELTENHAM",
        "VAUXHALLCROSS", "CENTURYHOUSE",
        "BLETCHLEY", "BLETCHLEYPARK",
    ],
    # Group 2 - British Crypto
    "crypto": [
        "ENIGMA", "TURING", "ALANTURING", "TYPEX", "ULTRA",
        "COLOSSUS", "TUNNY", "LORENZ", "BOMBE", "BOMBA", "HUTS",
    ],
    # Group 3 - Operation Gold/Stopwatch specific
    "opengold": [
        "CHECKPOINT", "CHARLIE", "CHECKPOINTCHARLIE",
        "FRIEDRICHSTRASSE", "GEORGEBLAKE",
        "HARVEYSHARVEY", "RUDOW",
    ],
    # Group 4 - NATO phonetic from Kryptos anomalies
    "nato": [
        "TANGO", "YANKEE", "ALFA", "ROMEO",
        "YANKEEALFAROMEO", "TANGOCHARLIE",
        "ECHOCHARLIEUNIFORMALFA",
    ],
    # Group 5 - Combined/creative
    "combined": [
        "STOPWATCHGOLD", "GOLDENSTOPWATCH", "TUNNELVISION",
        "BERLINWALL", "WALLFALL", "IRONCHURCHILL", "CURTAIN",
    ],
}

ALL_KEYWORDS = []
for group, words in KEYWORDS.items():
    for w in words:
        ALL_KEYWORDS.append((group, w))

# ── Cipher decrypt functions ─────────────────────────────────────────────

def decrypt_vig(ct_num, key_nums):
    """Vigenere decrypt: P = (C - K) mod 26."""
    klen = len(key_nums)
    return [(ct_num[i] - key_nums[i % klen]) % MOD for i in range(len(ct_num))]

def decrypt_beau(ct_num, key_nums):
    """Beaufort decrypt: P = (K - C) mod 26."""
    klen = len(key_nums)
    return [(key_nums[i % klen] - ct_num[i]) % MOD for i in range(len(ct_num))]

def decrypt_varbeau(ct_num, key_nums):
    """Variant Beaufort decrypt: P = (C + K) mod 26."""
    klen = len(key_nums)
    return [(ct_num[i] + key_nums[i % klen]) % MOD for i in range(len(ct_num))]

DECRYPT_FNS = {
    "vig": decrypt_vig,
    "beau": decrypt_beau,
    "varbeau": decrypt_varbeau,
}

# ── Scoring ──────────────────────────────────────────────────────────────

def score_pt_nums(pt_nums):
    """Score plaintext numeric values against cribs. Returns crib count."""
    matches = 0
    for pos in CRIB_POS:
        if pos < len(pt_nums) and pt_nums[pos] == CRIB_PT_NUM[pos]:
            matches += 1
    return matches

def score_pt_nums_detail(pt_nums):
    """Score with ENE/BC breakdown."""
    ene = 0
    bc = 0
    for pos in CRIB_POS:
        if pos < len(pt_nums) and pt_nums[pos] == CRIB_PT_NUM[pos]:
            if 21 <= pos <= 33:
                ene += 1
            elif 63 <= pos <= 73:
                bc += 1
    return ene + bc, ene, bc

def nums_to_text(nums):
    return "".join(ALPH[n % MOD] for n in nums)

# ── Main sweep ───────────────────────────────────────────────────────────

def main():
    random.seed(42)  # Deterministic

    print("=" * 70)
    print("E-OPGOLD-03: British Intelligence / MI6 / Five Eyes Keywords")
    print("=" * 70)
    print(f"Keywords: {len(ALL_KEYWORDS)}")
    print(f"Cipher variants: vig, beau, varbeau")
    print(f"Transpositions: identity + columnar w8 (all 40320) + w13 (1002) + w16 (1002)")
    print()

    t0 = time.time()
    top_results = []
    total_configs = 0
    REPORT_THRESHOLD = 7  # Report anything >= 7 cribs

    # Pre-generate column orderings for widths 13 and 16
    w13_orderings = [list(range(13)), list(range(12, -1, -1))]
    for _ in range(1000):
        p = list(range(13))
        random.shuffle(p)
        w13_orderings.append(p)

    w16_orderings = [list(range(16)), list(range(15, -1, -1))]
    for _ in range(1000):
        p = list(range(16))
        random.shuffle(p)
        w16_orderings.append(p)

    for group, keyword in ALL_KEYWORDS:
        key_nums = [ALPH_IDX[c] for c in keyword]
        klen = len(key_nums)

        # ── Phase 1: Identity transposition (no transposition) ──
        for vname, dfn in DECRYPT_FNS.items():
            pt_nums = dfn(CT_NUM, key_nums)
            score, ene, bc = score_pt_nums_detail(pt_nums)
            total_configs += 1

            if score >= REPORT_THRESHOLD:
                top_results.append({
                    "score": score,
                    "ene": ene,
                    "bc": bc,
                    "group": group,
                    "keyword": keyword,
                    "variant": vname,
                    "transposition": "identity",
                    "width": 0,
                    "col_order": None,
                    "plaintext": nums_to_text(pt_nums),
                })

        # ── Phase 2: Columnar transposition at Bean-compatible widths ──
        # Model: CT was produced by encrypt(transpose(PT)), so we
        # decrypt by: first undo substitution, then undo transposition.
        # Actually the two possible orderings are:
        #   Model A: CT = Sub(Trans(PT)) => PT = InvTrans(InvSub(CT))
        #   Model B: CT = Trans(Sub(PT)) => PT = InvSub(InvTrans(CT))
        # We test both.

        for width, orderings in [(8, None), (13, w13_orderings), (16, w16_orderings)]:
            if width == 8:
                iter_orderings = itertools.permutations(range(8))
                n_orders = 40320
            else:
                iter_orderings = iter(orderings)
                n_orders = len(orderings)

            for col_order in iter_orderings:
                col_order = list(col_order)
                # Build columnar perm and its inverse
                perm = columnar_perm(width, col_order, N)
                inv = invert_perm(perm)

                for vname, dfn in DECRYPT_FNS.items():
                    # Model A: PT = InvTrans(InvSub(CT))
                    intermediate_a = dfn(CT_NUM, key_nums)
                    pt_nums_a = [intermediate_a[inv[i]] for i in range(N)]
                    score_a, ene_a, bc_a = score_pt_nums_detail(pt_nums_a)
                    total_configs += 1

                    if score_a >= REPORT_THRESHOLD:
                        top_results.append({
                            "score": score_a,
                            "ene": ene_a,
                            "bc": bc_a,
                            "group": group,
                            "keyword": keyword,
                            "variant": vname,
                            "transposition": f"col_w{width}_modelA",
                            "width": width,
                            "col_order": col_order,
                            "plaintext": nums_to_text(pt_nums_a),
                        })

                    # Model B: PT = InvSub(InvTrans(CT))
                    ct_untrans = [CT_NUM[inv[i]] for i in range(N)]
                    pt_nums_b = dfn(ct_untrans, key_nums)
                    score_b, ene_b, bc_b = score_pt_nums_detail(pt_nums_b)
                    total_configs += 1

                    if score_b >= REPORT_THRESHOLD:
                        top_results.append({
                            "score": score_b,
                            "ene": ene_b,
                            "bc": bc_b,
                            "group": group,
                            "keyword": keyword,
                            "variant": vname,
                            "transposition": f"col_w{width}_modelB",
                            "width": width,
                            "col_order": col_order,
                            "plaintext": nums_to_text(pt_nums_b),
                        })

            # Progress
            elapsed = time.time() - t0
            print(f"  [{keyword}] w{width} done | configs={total_configs:,} | elapsed={elapsed:.1f}s")

    elapsed = time.time() - t0

    # Sort results
    top_results.sort(key=lambda x: -x["score"])

    # Summary
    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    print(f"  Total configs tested: {total_configs:,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Results >= {REPORT_THRESHOLD}/24: {len(top_results)}")
    print()

    # Score distribution
    score_dist = defaultdict(int)
    for r in top_results:
        score_dist[r["score"]] += 1
    print(f"  Score distribution (>={REPORT_THRESHOLD}/24):")
    for s in sorted(score_dist, reverse=True):
        print(f"    {s}/24: {score_dist[s]} configs")

    # Top 30
    print(f"\n  Top 30 results:")
    for i, r in enumerate(top_results[:30]):
        co_str = ""
        if r["col_order"] is not None:
            co_str = f" order={r['col_order']}"
        print(f"    {i+1:>2}. {r['score']}/24 (E{r['ene']}/B{r['bc']})"
              f"  {r['keyword']:<25} {r['variant']:<8}"
              f"  {r['transposition']:<20}{co_str}")
        # Show plaintext snippet around cribs
        pt = r["plaintext"]
        print(f"        PT[18..37]={pt[18:38]}  PT[60..77]={pt[60:78]}")

    # Global best
    global_best = top_results[0]["score"] if top_results else 0
    if global_best >= 18:
        verdict = "SIGNAL"
    elif global_best >= 10:
        verdict = "INVESTIGATE"
    elif global_best >= 7:
        verdict = "MARGINAL"
    else:
        verdict = "NOISE"

    print(f"\n  Global best: {global_best}/24")
    print(f"  Verdict: {verdict}")

    # Save results
    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-OPGOLD-03",
        "description": "British Intelligence / MI6 / Five Eyes keyword sweep",
        "total_configs": total_configs,
        "elapsed_seconds": elapsed,
        "n_keywords": len(ALL_KEYWORDS),
        "global_best_score": global_best,
        "verdict": verdict,
        "top_results": top_results[:200],
    }
    with open("results/e_opgold_03_british.json", "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_opgold_03_british.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_opgold_03_british.py")


if __name__ == "__main__":
    main()
