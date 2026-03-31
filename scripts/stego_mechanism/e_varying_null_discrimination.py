#!/usr/bin/env python3
"""
Varying Null Discrimination — Score all C(15,7) = 6,435 candidate masks.

Given 17 consensus nulls + 15 candidates for 7 varying nulls, evaluate
every possible complete 24-null mask using multiple discriminators:

1. IC of the 73-char real CT (higher = more structure)
2. Quadgram score of the 73-char real CT
3. Distinct letter count in null set (fewer = more restricted)
4. VP-1 consistency (how many of the 6 core VP-1 positions included)
5. Null gap regularity (std dev of gaps between consecutive nulls)
6. Whether all varying nulls fall in known varying ranges

Output: results/stego_mechanism/varying_null_discrimination.json
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys, os, json, math
from collections import Counter
from datetime import datetime, timezone
from itertools import combinations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_POSITIONS, ALPH, ALPH_IDX, MOD,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)

# ── Constants ───────────────────────────────────────────────────────
CONSENSUS = frozenset(CONSENSUS_NULL_POSITIONS)  # 17 positions
CANDIDATES = [4, 15, 17, 35, 37, 39, 40, 43, 49, 50, 55, 82, 87, 90, 94]
VP1_CORE = frozenset({39, 40, 43, 55, 87, 94})  # 6 VP-1 positions
VARYING_RANGES = [range(38, 46), range(55, 57), range(87, 89), range(93, 97)]
PALETTE_NUMS = frozenset(ALPH_IDX[c] for c in NULL_PALETTE)
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)

# ── Load quadgram data ──────────────────────────────────────────────
QUAD_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
with open(QUAD_PATH) as f:
    QUADGRAMS = json.load(f)
QUAD_FLOOR = min(QUADGRAMS.values()) - 1  # floor for missing quadgrams


def quadgram_score(text):
    """Log-probability score of text under English quadgram model."""
    score = 0.0
    for i in range(len(text) - 3):
        quad = text[i:i+4]
        score += QUADGRAMS.get(quad, QUAD_FLOOR)
    return score / max(1, len(text) - 3)  # normalize by length


def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def in_varying_ranges(pos):
    """Check if position falls in any known varying range."""
    return any(pos in r for r in VARYING_RANGES)


def score_mask(varying_7):
    """Score a complete 24-null mask (17 consensus + 7 varying)."""
    all_nulls = CONSENSUS | frozenset(varying_7)
    real_positions = sorted(set(range(CT_LEN)) - all_nulls)
    real_text = "".join(CT[p] for p in real_positions)
    null_text = "".join(CT[p] for p in sorted(all_nulls))

    # 1. IC of real text
    real_ic = ic(real_text)

    # 2. Quadgram score
    real_qg = quadgram_score(real_text)

    # 3. Distinct letters in null set
    null_distinct = len(set(null_text))

    # 4. VP-1 consistency
    vp1_count = len(VP1_CORE & frozenset(varying_7))

    # 5. Gap regularity (std dev of gaps between consecutive nulls)
    sorted_nulls = sorted(all_nulls)
    gaps = [sorted_nulls[i+1] - sorted_nulls[i] for i in range(len(sorted_nulls)-1)]
    gap_mean = sum(gaps) / len(gaps) if gaps else 0
    gap_std = math.sqrt(sum((g - gap_mean)**2 for g in gaps) / len(gaps)) if gaps else 0

    # 6. All varying in known ranges?
    all_in_ranges = all(in_varying_ranges(p) for p in varying_7)

    # 7. Letter frequency chi-square of real text vs uniform
    freq = Counter(real_text)
    expected = len(real_text) / 26
    chi2 = sum((freq.get(chr(65+i), 0) - expected)**2 / expected for i in range(26))

    # 8. Palette letter count in varying nulls (should be 0 by construction,
    #    but check non-palette character diversity)
    varying_chars = [CT[p] for p in varying_7]
    varying_distinct = len(set(varying_chars))

    return {
        "varying": list(varying_7),
        "varying_chars": varying_chars,
        "real_ic": round(real_ic, 6),
        "quadgram": round(real_qg, 4),
        "null_distinct": null_distinct,
        "vp1_count": vp1_count,
        "gap_std": round(gap_std, 2),
        "all_in_ranges": all_in_ranges,
        "chi2": round(chi2, 2),
        "varying_distinct": varying_distinct,
        "real_len": len(real_text),
    }


def main():
    results = {
        "experiment": "e_varying_null_discrimination",
        "date": datetime.now(timezone.utc).isoformat(),
        "consensus_nulls": sorted(CONSENSUS),
        "candidates": CANDIDATES,
        "vp1_core": sorted(VP1_CORE),
        "total_masks": 0,
    }

    print("=" * 80)
    print(f"VARYING NULL DISCRIMINATION — C({len(CANDIDATES)},7) = "
          f"{math.comb(len(CANDIDATES), 7)} masks")
    print("=" * 80)

    # ── Score all masks ─────────────────────────────────────────────
    all_scores = []
    for combo in combinations(CANDIDATES, 7):
        score = score_mask(combo)
        all_scores.append(score)

    results["total_masks"] = len(all_scores)
    print(f"\nScored {len(all_scores)} masks")

    # ── Analyze distributions ───────────────────────────────────────
    ics = [s["real_ic"] for s in all_scores]
    qgs = [s["quadgram"] for s in all_scores]
    dists = [s["null_distinct"] for s in all_scores]
    vp1s = [s["vp1_count"] for s in all_scores]
    chi2s = [s["chi2"] for s in all_scores]

    print(f"\n── Discriminator Distributions ──")
    for name, vals in [("IC", ics), ("Quadgram", qgs), ("Null distinct", dists),
                       ("VP1 count", vp1s), ("Chi2", chi2s)]:
        print(f"  {name:15s}: min={min(vals):.4f}  max={max(vals):.4f}  "
              f"range={max(vals)-min(vals):.4f}  mean={sum(vals)/len(vals):.4f}")

    results["distributions"] = {
        "ic": {"min": min(ics), "max": max(ics), "range": max(ics)-min(ics)},
        "quadgram": {"min": min(qgs), "max": max(qgs), "range": max(qgs)-min(qgs)},
        "null_distinct": {"min": min(dists), "max": max(dists)},
        "chi2": {"min": min(chi2s), "max": max(chi2s)},
    }

    # ── VP-1 constrained masks (6 core + 1 wildcard) ───────────────
    print(f"\n── VP-1 Constrained Masks (6 core + 1 wildcard) ──")
    non_core = [p for p in CANDIDATES if p not in VP1_CORE]
    vp1_masks = []
    for wildcard in non_core:
        varying_7 = tuple(sorted(VP1_CORE | {wildcard}))
        score = score_mask(varying_7)
        score["wildcard"] = wildcard
        score["wildcard_char"] = CT[wildcard]
        vp1_masks.append(score)
        in_range = "✓" if in_varying_ranges(wildcard) else "✗"
        print(f"  +{wildcard:2d} ({CT[wildcard]}) {in_range}  IC={score['real_ic']:.6f}  "
              f"QG={score['quadgram']:.4f}  null_dist={score['null_distinct']}  "
              f"chi2={score['chi2']:.1f}  gaps={score['gap_std']:.1f}")

    results["vp1_constrained"] = vp1_masks

    # ── Rank VP-1 masks by composite score ──────────────────────────
    # Higher IC = better, higher quadgram = better, lower chi2 = better,
    # lower gap_std = more regular
    print(f"\n── VP-1 Masks Ranked by IC ──")
    vp1_by_ic = sorted(vp1_masks, key=lambda s: -s["real_ic"])
    for i, s in enumerate(vp1_by_ic):
        print(f"  #{i+1}: +{s['wildcard']:2d} ({s['wildcard_char']})  "
              f"IC={s['real_ic']:.6f}  QG={s['quadgram']:.4f}")

    print(f"\n── VP-1 Masks Ranked by Quadgram ──")
    vp1_by_qg = sorted(vp1_masks, key=lambda s: -s["quadgram"])
    for i, s in enumerate(vp1_by_qg):
        print(f"  #{i+1}: +{s['wildcard']:2d} ({s['wildcard_char']})  "
              f"QG={s['quadgram']:.4f}  IC={s['real_ic']:.6f}")

    # ── Best overall masks (any 7 of 15) ────────────────────────────
    print(f"\n── Top 10 Masks by IC (all 6,435) ──")
    by_ic = sorted(all_scores, key=lambda s: -s["real_ic"])
    for i, s in enumerate(by_ic[:10]):
        vp1_tag = f"VP1={s['vp1_count']}" if s['vp1_count'] < 6 else "VP1=6✓"
        print(f"  #{i+1}: {s['varying']}  IC={s['real_ic']:.6f}  "
              f"QG={s['quadgram']:.4f}  {vp1_tag}")

    results["top10_by_ic"] = by_ic[:10]

    print(f"\n── Top 10 Masks by Quadgram (all 6,435) ──")
    by_qg = sorted(all_scores, key=lambda s: -s["quadgram"])
    for i, s in enumerate(by_qg[:10]):
        vp1_tag = f"VP1={s['vp1_count']}" if s['vp1_count'] < 6 else "VP1=6✓"
        print(f"  #{i+1}: {s['varying']}  QG={s['quadgram']:.4f}  "
              f"IC={s['real_ic']:.6f}  {vp1_tag}")

    results["top10_by_quadgram"] = by_qg[:10]

    # ── Discrimination power assessment ─────────────────────────────
    print(f"\n── Discrimination Power ──")
    ic_range = max(ics) - min(ics)
    qg_range = max(qgs) - min(qgs)
    # How much do the top masks separate from the median?
    median_ic = sorted(ics)[len(ics)//2]
    median_qg = sorted(qgs)[len(qgs)//2]
    top_ic = max(ics)
    top_qg = max(qgs)

    print(f"  IC: top={top_ic:.6f}, median={median_ic:.6f}, "
          f"gap={top_ic-median_ic:.6f}, range={ic_range:.6f}")
    print(f"  QG: top={top_qg:.4f}, median={median_qg:.4f}, "
          f"gap={top_qg-median_qg:.4f}, range={qg_range:.4f}")

    # Is the discrimination meaningful?
    # For IC: random expectation for 73 chars is ~0.0385 with sigma ~0.02
    # A range of 0.001 is not discriminating. A range of 0.01 might be.
    if ic_range < 0.005:
        disc_verdict = "WEAK — IC range too small to discriminate"
    elif ic_range < 0.01:
        disc_verdict = "MARGINAL — IC range allows partial discrimination"
    else:
        disc_verdict = "STRONG — IC range sufficient for discrimination"
    print(f"  Assessment: {disc_verdict}")

    results["discrimination"] = {
        "ic_range": ic_range,
        "qg_range": qg_range,
        "ic_top_vs_median": top_ic - median_ic,
        "qg_top_vs_median": top_qg - median_qg,
        "verdict": disc_verdict,
    }

    # ── Consensus pick ──────────────────────────────────────────────
    # If VP-1 constrained AND top-ranked, that's our best candidate
    print(f"\n── Best Candidate ──")
    # Among VP-1 masks, which has best composite rank?
    for s in vp1_masks:
        s["ic_rank"] = sum(1 for x in all_scores if x["real_ic"] > s["real_ic"]) + 1
        s["qg_rank"] = sum(1 for x in all_scores if x["quadgram"] > s["quadgram"]) + 1
        s["composite_rank"] = s["ic_rank"] + s["qg_rank"]

    best_vp1 = min(vp1_masks, key=lambda s: s["composite_rank"])
    print(f"  Best VP-1 mask: +{best_vp1['wildcard']} ({best_vp1['wildcard_char']})")
    print(f"    IC rank: {best_vp1['ic_rank']}/{len(all_scores)}")
    print(f"    QG rank: {best_vp1['qg_rank']}/{len(all_scores)}")
    print(f"    Composite: {best_vp1['composite_rank']}")
    print(f"    Full varying set: {best_vp1['varying']}")
    print(f"    Varying chars: {best_vp1['varying_chars']}")

    # Also show the absolute best mask (any 7 of 15)
    for s in all_scores:
        s["ic_rank"] = sum(1 for x in all_scores if x["real_ic"] > s["real_ic"]) + 1
        s["qg_rank"] = sum(1 for x in all_scores if x["quadgram"] > s["quadgram"]) + 1
        s["composite_rank"] = s["ic_rank"] + s["qg_rank"]

    best_overall = min(all_scores, key=lambda s: s["composite_rank"])
    print(f"\n  Best overall mask: {best_overall['varying']}")
    print(f"    IC rank: {best_overall['ic_rank']}/{len(all_scores)}")
    print(f"    QG rank: {best_overall['qg_rank']}/{len(all_scores)}")
    print(f"    Composite: {best_overall['composite_rank']}")
    print(f"    VP1 count: {best_overall['vp1_count']}/6")

    results["best_vp1_mask"] = best_vp1
    results["best_overall_mask"] = best_overall

    # ── Write full 73-char text for best candidate ──────────────────
    best_nulls = CONSENSUS | frozenset(best_vp1["varying"])
    best_real = sorted(set(range(CT_LEN)) - best_nulls)
    best_real_text = "".join(CT[p] for p in best_real)
    print(f"\n  73-char real CT (best VP-1): {best_real_text}")
    results["best_vp1_real_text"] = best_real_text
    results["best_vp1_null_positions"] = sorted(best_nulls)

    # Also write for best overall
    best_o_nulls = CONSENSUS | frozenset(best_overall["varying"])
    best_o_real = sorted(set(range(CT_LEN)) - best_o_nulls)
    best_o_text = "".join(CT[p] for p in best_o_real)
    print(f"  73-char real CT (best overall): {best_o_text}")
    results["best_overall_real_text"] = best_o_text

    # ── Final verdict ───────────────────────────────────────────────
    print(f"\n{'=' * 80}")
    if ic_range >= 0.005 and best_vp1["ic_rank"] <= 100:
        print(f"VERDICT: VP-1 mask (+{best_vp1['wildcard']}) is a STRONG candidate")
        results["verdict"] = f"STRONG_CANDIDATE_+{best_vp1['wildcard']}"
    elif ic_range >= 0.002:
        print(f"VERDICT: MARGINAL discrimination — VP-1 mask (+{best_vp1['wildcard']}) "
              f"is best available but not clearly distinguished")
        results["verdict"] = f"MARGINAL_+{best_vp1['wildcard']}"
    else:
        print("VERDICT: INDISCRIMINATE — all masks produce similar statistics")
        results["verdict"] = "INDISCRIMINATE"
    print(f"{'=' * 80}")

    out_path = os.path.join(_ROOT, "results", "stego_mechanism",
                            "varying_null_discrimination.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults written to {out_path}")


if __name__ == "__main__":
    main()
