#!/usr/bin/env python3
"""Canonical re-verification of flagged historical K4 candidates.

Goal: never trust a result file's self-reported status/score. For every
plaintext candidate we can extract, re-run the canonical kernel scorer
(kryptos.kernel.scoring.aggregate.score_candidate) from a clean interpreter
and report crib_score, bean_passed, ngram_score, classification, plus a
"forced-crib" diagnosis (cribs match but n-gram score is at noise floor =>
the cribs were pasted in, not produced by a real decryption).

Usage:
    PYTHONPATH=src python3 results/final_k4_goal/verify_candidates.py

Reproducible: reads only result JSONs under results/ and kernel constants.
"""
import json
import os
import sys

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate

RESULTS = os.path.join(os.path.dirname(__file__), "..")

# (file stem, list of dotted/loose paths to try for a plaintext string)
FLAGGED = [
    "test_6f4ade3ecf9f_boustrophedon",
    "e_ct_mutation_nullmask_beaufort",
    "e_carter_transposition_optimized_01",
    "e_team_targeted_homo_trans",
    "e_team_homophonic_trans",
    "fresh_mcmc_attack",
    "e_s_13_keyword_transposition",
    "e_s_15_creative_keys",
    "e_s_35_null_cipher",
]

# n-gram noise floor: random_text null mean ~ -6.43 (see null_baselines manifest).
# A real English plaintext scores roughly -7..-9 per-quadgram-mean *higher*
# (less negative) than noise; here ngram_score is a sum. We flag "forced" when
# crib_score is high but ngram_score is in the bottom region for a 97-char text.
NGRAM_NOISE_CEIL = -270.0  # sums below this are gibberish-grade for n=97


def looks_like_pt(s):
    return isinstance(s, str) and len(s) == 97 and s.isalpha() and s.isupper()


def harvest_plaintexts(obj, found):
    """Recursively collect any 97-char A-Z uppercase string."""
    if isinstance(obj, str):
        if looks_like_pt(obj):
            found.add(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            harvest_plaintexts(v, found)
    elif isinstance(obj, list):
        for v in obj:
            harvest_plaintexts(v, found)


def crib_overlay_check(pt):
    """How many of the 24 crib positions does this PT satisfy, and is the
    rest gibberish? Returns (crib_hits, total_cribs)."""
    hits = 0
    for pos, ch in CRIB_POSITIONS.items():
        if pos < len(pt) and pt[pos] == ch:
            hits += 1
    return hits, len(CRIB_POSITIONS)


def main():
    rows = []
    for stem in FLAGGED:
        path = os.path.join(RESULTS, f"{stem}.json")
        if not os.path.exists(path):
            rows.append((stem, "NO_FILE", None, None, None, None, ""))
            continue
        try:
            d = json.load(open(path))
        except Exception as e:
            rows.append((stem, f"LOAD_ERR:{e}", None, None, None, None, ""))
            continue
        self_status = ""
        if isinstance(d, dict):
            self_status = str(d.get("status") or d.get("verdict")
                              or d.get("classification") or "")[:40]
        found = set()
        harvest_plaintexts(d, found)
        if not found:
            rows.append((stem, "NO_97CHAR_PT", None, None, None, None, self_status))
            continue
        # Score every harvested PT; keep the best by canonical crib_score.
        best = None
        for pt in found:
            bd = score_candidate(pt)
            crib = bd.crib_score
            if best is None or crib > best[1].crib_score:
                best = (pt, bd)
        pt, bd = best
        crib = bd.crib_score
        bean = bd.bean_passed
        ng = bd.ngram_score
        cls = bd.crib_classification
        forced = (crib is not None and crib >= 18 and ng is not None
                  and ng < NGRAM_NOISE_CEIL)
        diag = f"FORCED-CRIB" if forced else ""
        rows.append((stem, f"self={self_status}", crib, bean, ng, cls,
                     f"n_pt={len(found)} {diag}"))

    # Print table
    print("=" * 110)
    print("CANONICAL RE-VERIFICATION OF FLAGGED CANDIDATES")
    print(f"CT len={len(CT)}  cribs={len(CRIB_POSITIONS)}  scorer=score_candidate (anchored)")
    print("=" * 110)
    hdr = f"{'candidate':40s} {'crib':>4s} {'bean':>5s} {'ngram':>9s} {'class':>12s} {'notes'}"
    print(hdr)
    print("-" * 110)
    out = []
    for stem, status, crib, bean, ng, cls, notes in rows:
        cribs = f"{crib}" if crib is not None else "-"
        beans = f"{bean}" if bean is not None else "-"
        ngs = f"{ng:.1f}" if isinstance(ng, (int, float)) else "-"
        clss = f"{cls}" if cls else "-"
        print(f"{stem:40s} {cribs:>4s} {beans:>5s} {ngs:>9s} {str(clss):>12s} {notes}")
        out.append(dict(candidate=stem, self_status=status, crib_score=crib,
                        bean_passed=bean, ngram_score=ng, classification=str(cls),
                        notes=notes))
    print("-" * 110)
    print("NOTE: 'FORCED-CRIB' = crib_score>=18 but ngram_score below gibberish")
    print("      ceiling => the cribs are pasted, the body is noise. Not a solve.")
    json.dump(out, open(os.path.join(os.path.dirname(__file__),
              "verified_candidates.json"), "w"), indent=2)
    print("\nWrote verified_candidates.json")


if __name__ == "__main__":
    main()
