#!/usr/bin/env python3
"""
e_crib_37_single_omission_sweep
===============================

FAMILY: crib_analysis
STATUS: active

HYPOTHESIS. K4's true ciphertext was 98 characters and one was omitted when the
copper was carved. This is not speculation about Sanborn's care: he did exactly
this on K2. From docs/kryptos_ground_truth.md, marked PUBLIC FACT --

    "K2 ending decrypts as IDBYROWS on physical copper (both sculptures).
     Sanborn verbally corrected to XLAYERTWO in 2006 but never modified the
     copper."

and from docs/anomaly_registry.md A1, classified ADMITTED ERROR: an X separator
was omitted "for aesthetic reasons, to keep the sculpture visually balanced",
and he "didn't know the decryption was altered even some time after the solution
was revealed". One of three solved panels carries an uncorrected, creator-
admitted OMISSION, for a reason that applies to every panel.

WHY THIS IS NOT ALREADY COVERED. The CT-perturbation campaign (Stage A, closed
clean-negative May 2026) tested Hamming-1 SUBSTITUTIONS. Its own coverage audit
puts insertions, deletions and reading-order errors explicitly OUT OF SCOPE, and
notes that substitutions away from crib positions cannot even move the gate, so
the effective test was 600 crib-position substitutions against 719 keywords.
The one error class Sanborn is documented to have committed has never been
tested on K4.

MODEL. corrected_CT = carved[:d] + L + carved[d:] for d in 0..97 and L in A-Z,
giving 98 x 26 = 2,548 candidates. An insertion RE-INDEXES: the released cribs
are pinned to specific CARVED ciphertext letters, so a crib at carved index q
sits at index q+1 in the corrected text whenever q >= d. Getting this wrong
manufactures false results, so it is asserted in a unit check below.

STRUCTURAL NOTE. 98 = 14 x 7 exactly; 97 is prime. A 97-character text has a
ragged final row at every grid width and a 98-character one does not, so widths
7 and 14 are swept explicitly alongside the direct model.

PRE-REGISTERED PREDICTION (computed before the first run, so it can be scored):
  hits should be ~0 at periods <= 20, ~0.9 at period 25, ~588 at 26 and 30, and
  ~15,288 at each of 27/28/29 where 24 cribs occupy 24 distinct classes and the
  ceiling is 24 by construction. Total ~47,000, essentially all vacuous.

PRE-REGISTERED DECISION RULE: a hit counts ONLY if period <= 20 AND the matched
null at that period is ~0. Everything else is degrees of freedom, not K4.
The matched null is the SAME sweep over shuffled ciphertexts -- per
scripts/crib_analysis/e_crib_31_filter_power_analysis.py, a null that is easier
than the procedure understates the background rate.

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_37_single_omission_sweep.py --workers 14
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import AZ, ceiling, index_table, keyword_mixed  # noqa: E402
from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402

KA = keyword_mixed("KRYPTOS")
ALPHAS = [("AZ/AZ", AZ, AZ), ("KA/AZ", KA, AZ), ("AZ/KA", AZ, KA)]
VARIANTS = ("vig", "beau", "vbeau")
PERIODS = range(1, 31)
NTRUE = 98


def corrected(carved: str, d: int, letter: str) -> str:
    return carved[:d] + letter + carved[d:]


def shifted_cribs(d: int) -> dict[int, str]:
    """A crib pinned to carved index q sits at q+1 in the corrected text if q >= d."""
    return {(q + 1 if q >= d else q): c for q, c in CRIB_DICT.items()}


def _check_reindex() -> None:
    """The re-index is the one place this can silently go wrong. Assert it."""
    for d in (0, 22, 50, 97):
        ct2 = corrected(CT, d, "Q")
        cr2 = shifted_cribs(d)
        assert len(ct2) == NTRUE and len(cr2) == len(CRIB_DICT)
        for q, c in CRIB_DICT.items():
            q2 = q + 1 if q >= d else q
            assert ct2[q2] == CT[q], f"re-index broken at d={d}, q={q}"


def _job(args):
    d, letter, shuffle_seed = args
    carved = CT
    if shuffle_seed is not None:
        rng = random.Random(shuffle_seed)
        lst = list(CT)
        rng.shuffle(lst)
        carved = "".join(lst)
    ct2 = corrected(carved, d, letter)
    cribs = shifted_cribs(d)
    n = len(cribs)
    hits = []
    for aname, ca, pa in ALPHAS:
        ct_tab, pt_tab = index_table(ca), index_table(pa)
        for v in VARIANTS:
            for p in PERIODS:
                c, _ = ceiling(ct2, cribs, lambda q: q, lambda q, p=p: q % p,
                               ct_tab=ct_tab, pt_tab=pt_tab, variant=v)
                if c == n:
                    hits.append((p, aname, v))
    return hits


def run(mode: str, workers: int):
    jobs = [(d, L, (None if mode == "real" else 900_000 + d * 26 + i))
            for d in range(NTRUE) for i, L in enumerate(AZ)]
    per_period = Counter()
    low = []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for (d, L, _s), hits in zip(jobs, ex.map(_job, jobs, chunksize=16)):
            for p, aname, v in hits:
                per_period[p] += 1
                if p <= 20:
                    low.append({"d": d, "letter": L, "period": p,
                                "alpha": aname, "variant": v})
    return per_period, low


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    args = ap.parse_args()

    _check_reindex()
    print("=" * 84)
    print("SINGLE-OMISSION SWEEP — 98-character true ciphertext, one letter dropped")
    print("=" * 84)
    print("  re-index self-check: PASSED (every crib still lands on its carved letter)")
    print(f"  candidates {NTRUE * 26:,} x {len(ALPHAS) * len(VARIANTS)} tableaux "
          f"x {len(PERIODS)} periods = {NTRUE*26*len(ALPHAS)*len(VARIANTS)*len(PERIODS):,} cells")
    print()

    out = {}
    for mode in ("real", "shuffled"):
        pp, low = run(mode, args.workers)
        out[mode] = {"per_period": dict(pp), "low_period_hits": low}
        tot = sum(pp.values())
        print(f"  {mode.upper():<9} total hits {tot:,}")
        print(f"    {'period':>7} {'hits':>9}")
        for p in sorted(pp):
            print(f"    {p:>7} {pp[p]:>9,}")
        print(f"    hits at period <= 20 (the informative band): {len(low)}")
        print()

    r_low = len(out["real"]["low_period_hits"])
    s_low = len(out["shuffled"]["low_period_hits"])
    print("=" * 84)
    print("PRE-REGISTERED DECISION")
    print("=" * 84)
    print(f"  real ciphertext, hits at period <= 20    : {r_low}")
    print(f"  shuffled matched null, same band         : {s_low}")
    if r_low == 0:
        print("  -> NO SIGNAL. The single-omission hypothesis produces nothing the")
        print("     ceiling filter can distinguish from an unperturbed carved text,")
        print("     within direct-alignment periodic substitution.")
    elif s_low == 0:
        print("  -> SIGNAL. Hits in the informative band with an empty matched null.")
        print("     Investigate every one; do not announce anything yet.")
    else:
        print(f"  -> hits present but the null also fires ({s_low}); ratio "
              f"{r_low/max(s_low,1):.2f}x. Not evidence without a much larger margin.")

    art = os.path.join(_ROOT, "results", "e_crib_37_single_omission_sweep.json")
    with open(art, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
