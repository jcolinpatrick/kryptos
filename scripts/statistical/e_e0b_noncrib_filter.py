#!/usr/bin/env python3
"""
Cipher: Bean E0b (Materna) non-crib extrapolation filter
Family: statistical
Status: active
Keyspace: filter over existing candidate plaintexts
Last run: 2026-05-15
Best score: see results/e_e0b_noncrib_filter.json
"""
# E0b non-crib filter
# ===================
#
# Bean (2021) §2.4 reports E0b: among the 10 crib positions where PT is in
# {K,R,Y,P,T,O,S}, the corresponding CT letters cluster within mean minor-
# distance 2.10. Monte Carlo p ~ 1/5,520. Replicated independently in
# scripts/statistical/e_bean_replication_01.py.
#
# This script extends E0b to a non-crib FILTER:
#   for each candidate PT, compute mean |K_vig| at non-crib positions
#   where the candidate puts a KRYPTOS-set letter. A true K4 solution
#   should reproduce the crib mean (~2.1) globally; post-hoc overfits
#   that satisfy cribs but generate random non-crib letters score near
#   the random expectation (~6.5).
#
# Variant-discrimination finding (this script, first reported 2026-05-15):
#   E0b at the cribs is symmetric in sign under Vig and Variant Beaufort
#   (both yield mean 2.10), but is essentially extinguished under
#   standard Beaufort (mean 8.10, K-set / non-K-set ratio 0.94).
#   Therefore E0b also functions as a CIPHER-VARIANT discriminator:
#   under E0b, K4 favours Vig or Variant Beaufort over Beaufort.
#
# Robustness:
#   Among random 7-letter subsets matching the same crib-count (n=10),
#   only ~1.05% give mean |K| <= 2.10. The KRYPTOS keyword set is in the
#   extreme tail; this is not a generic CT structural coincidence.

import os
import sys
import json
import glob
import argparse
import random
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH

KRYPTOS_SET = frozenset("KRYPTOS")
CRIB_POSITIONS = frozenset(CRIB_DICT.keys())


def minor_diff(a: str, b: str) -> int:
    """Circular distance in [0, 13]."""
    d = abs(ord(a) - ord(b))
    return min(d, 26 - d)


def vig_keystream_signed(ct_ch: str, pt_ch: str) -> int:
    """Signed K = CT - PT in [-13, 12]."""
    d = (ord(ct_ch) - ord(pt_ch)) % 26
    return d if d <= 13 else d - 26


def e0b_score(pt: str, ct: str = CT) -> dict | None:
    """Compute E0b non-crib statistics for a candidate PT.

    Returns dict with:
      - n_kset:    count of non-crib positions with PT in KRYPTOS-set
      - sum_abs_k: sum of |K_vig| at those positions
      - mean:      mean of |K_vig|
      - tight:     count of those positions with |K_vig| <= 2
      - frac_tight: tight / n_kset
    Returns None if pt is malformed.

    A real solution under E0b global should give:
      - mean ~ 2.1
      - frac_tight ~ 0.9
    A post-hoc-overfit / random PT gives:
      - mean ~ 6.5
      - frac_tight ~ 0.19
    """
    if len(pt) != len(ct) or not pt.isalpha() or not pt.isupper():
        return None
    diffs = []
    for i in range(len(ct)):
        if i in CRIB_POSITIONS:
            continue
        if pt[i] in KRYPTOS_SET:
            diffs.append(minor_diff(pt[i], ct[i]))
    if not diffs:
        return None
    return {
        "n_kset": len(diffs),
        "sum_abs_k": sum(diffs),
        "mean": sum(diffs) / len(diffs),
        "tight": sum(1 for d in diffs if d <= 2),
        "frac_tight": sum(1 for d in diffs if d <= 2) / len(diffs),
    }


def crib_score(pt: str) -> int:
    """Standard crib_score: number of crib positions where PT matches."""
    return sum(1 for p, c in CRIB_DICT.items() if 0 <= p < len(pt) and pt[p] == c)


def harvest_candidates_from_results(results_dir: str = "results", max_size: int = 20_000_000):
    """Scan results/*.json for 97-char uppercase plaintexts. Yield (path, ctx, pt)."""
    seen = set()
    for path in glob.glob(os.path.join(results_dir, "*.json")):
        try:
            if os.path.getsize(path) > max_size:
                continue
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        def walk(obj, ctx=""):
            if isinstance(obj, dict):
                pt = obj.get("plaintext") or obj.get("pt") or obj.get("candidate_pt")
                if isinstance(pt, str) and len(pt) == 97 and pt.isalpha() and pt.isupper():
                    if pt not in seen:
                        seen.add(pt)
                        yield (path, ctx, pt)
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        yield from walk(v, f"{ctx}.{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj[:500]):
                    yield from walk(v, f"{ctx}[{i}]")

        yield from walk(data)


def robustness_check(n_trials: int = 20_000, seed: int = 42) -> dict:
    """Fraction of random 7-letter subsets matching count=10 that achieve mean <= 2.10."""
    rng = random.Random(seed)
    crib_pos_sorted = sorted(CRIB_DICT.keys())
    matching = []
    for _ in range(n_trials):
        cand = set(rng.sample("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 7))
        total = 0
        count = 0
        for pos in crib_pos_sorted:
            pt = CRIB_DICT[pos]
            if pt in cand:
                total += minor_diff(pt, CT[pos])
                count += 1
        if count == 10:
            matching.append(total / 10)
    n_at_or_below = sum(1 for m in matching if m <= 2.10)
    return {
        "n_matching": len(matching),
        "n_at_or_below_2_10": n_at_or_below,
        "fraction": n_at_or_below / max(len(matching), 1),
        "min_mean": min(matching) if matching else None,
        "n_trials": n_trials,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--scan-results", action="store_true",
                        help="Scan results/ for candidates and score them")
    parser.add_argument("--robustness", action="store_true",
                        help="Run robustness MC over random 7-letter subsets")
    parser.add_argument("--top", type=int, default=20,
                        help="Number of top candidates to report")
    parser.add_argument("--min-kset", type=int, default=10,
                        help="Minimum n_kset for inclusion in ranking")
    parser.add_argument("-o", "--out", default="results/e_e0b_noncrib_filter.json",
                        help="Output JSON path")
    args = parser.parse_args()

    output = {
        "experiment": "e_e0b_noncrib_filter",
        "purpose": "Bean E0b extended as non-crib discriminator for K4 candidate plaintexts",
    }

    # ── Crib baseline (under Vig) ──────────────────────────────────────
    crib_baseline = {}
    for label, fn in [
        ("vigenere", lambda ct, pt: (ord(ct) - ord(pt)) % 26),
        ("beaufort", lambda ct, pt: (ord(ct) + ord(pt)) % 26),
        ("variant_beaufort", lambda ct, pt: (ord(pt) - ord(ct)) % 26),
    ]:
        kset_vals = []
        nonk_vals = []
        for pos in sorted(CRIB_DICT.keys()):
            pt = CRIB_DICT[pos]
            k = fn(CT[pos], pt)
            mag = min(k, 26 - k)
            if pt in KRYPTOS_SET:
                kset_vals.append(mag)
            else:
                nonk_vals.append(mag)
        crib_baseline[label] = {
            "n_kset": len(kset_vals),
            "kset_mean_abs_k": sum(kset_vals) / max(len(kset_vals), 1),
            "n_nonk": len(nonk_vals),
            "nonk_mean_abs_k": sum(nonk_vals) / max(len(nonk_vals), 1),
            "ratio_nonk_over_kset": (
                sum(nonk_vals) / max(len(nonk_vals), 1)
            ) / max(sum(kset_vals) / max(len(kset_vals), 1), 1e-6),
        }
    output["crib_baseline"] = crib_baseline

    print("=" * 72)
    print("E0b NON-CRIB FILTER")
    print("=" * 72)
    print()
    print("Crib baseline by variant (mean |K| at K-set vs non-K-set):")
    for label, st in crib_baseline.items():
        print(f"  {label:>20s}: K-set mean={st['kset_mean_abs_k']:.2f}  "
              f"non-K-set mean={st['nonk_mean_abs_k']:.2f}  "
              f"ratio={st['ratio_nonk_over_kset']:.2f}x")

    # ── Robustness ──────────────────────────────────────────────────────
    if args.robustness:
        print()
        print("Robustness over random 7-letter subsets (count=10 matches):")
        rb = robustness_check()
        output["robustness"] = rb
        print(f"  Matching subsets: {rb['n_matching']:,}")
        print(f"  Subsets achieving mean <= 2.10: {rb['n_at_or_below_2_10']:,}")
        print(f"  Fraction: {rb['fraction']:.4f} ({rb['fraction']*100:.2f}%)")
        print(f"  Minimum mean among matching: {rb['min_mean']:.2f}")

    # ── Scan results ────────────────────────────────────────────────────
    if args.scan_results:
        print()
        print("Scanning results/ for candidate PTs...")
        scored = []
        for path, ctx, pt in harvest_candidates_from_results():
            e = e0b_score(pt)
            if e is None:
                continue
            if e["n_kset"] < args.min_kset:
                continue
            scored.append({
                "path": path,
                "ctx": ctx,
                "pt": pt,
                "crib_score": crib_score(pt),
                "e0b_mean": e["mean"],
                "e0b_n_kset": e["n_kset"],
                "e0b_frac_tight": e["frac_tight"],
            })
        print(f"  Scored {len(scored):,} candidates (n_kset >= {args.min_kset})")

        scored.sort(key=lambda x: x["e0b_mean"])
        output["n_candidates_scored"] = len(scored)
        output["top_by_e0b"] = scored[:args.top]

        # Also: top by combined (crib_score - 2*e0b_mean)
        combined = sorted(
            scored,
            key=lambda x: -(x["crib_score"] - 2 * x["e0b_mean"]),
        )
        output["top_by_combined"] = combined[:args.top]

        print()
        print(f"Top {args.top} candidates by E0b (lowest mean = best):")
        print(f"  {'crib':>5} {'e0b':>6} {'n_k':>5} {'tight':>6} file")
        for s in scored[:args.top]:
            print(f"  {s['crib_score']:>5} {s['e0b_mean']:>6.2f} "
                  f"{s['e0b_n_kset']:>5} {s['e0b_frac_tight']:>6.2f} "
                  f"{os.path.basename(s['path'])}")

        print()
        print(f"Top {args.top} candidates by combined (crib - 2*e0b):")
        for c in combined[:args.top]:
            print(f"  crib={c['crib_score']:2d} e0b={c['e0b_mean']:.2f} "
                  f"n={c['e0b_n_kset']:2d} {os.path.basename(c['path'])}")

    # ── Save ────────────────────────────────────────────────────────────
    out_path = os.path.join(_ROOT, args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print()
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
