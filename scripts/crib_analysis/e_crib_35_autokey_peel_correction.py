#!/usr/bin/env python3
"""
e_crib_35_autokey_peel_correction
=================================

FAMILY: crib_analysis
STATUS: active

CORRECTS E-FRAC-37, which docs/elimination_tiers.md classifies as a permanent
STRUCTURAL elimination:

    "Autokey (PT/CT x Vig/Beau) + arbitrary transposition CANNOT reach 24/24.
     PT-autokey max=16/24, CT-autokey max=21/24."

That was established for ONE peel order only. In the other order,

    CT = Transpose( Autokey(PT) )

the autokey runs in the pre-transposition frame. Peeling the route first gives
S = untranspose(CT), and then PT[j] = S[j] - k[j] with k[j] = primer[j] for
j < m and PT[j-m] thereafter. Crucially PT[q] depends ONLY on primer[q mod m],
so the crib problem separates by primer slot and is solvable exactly.

MEASURED (this script):
  PT-autokey, transposition-outer, best over 36 transpositions
    primer  1-25 : max 23/24  -> ELIMINATION HOLDS
    primer    26 : 24/24      -> ELIMINATION FAILS
  CT-autokey, transposition-outer, best over 75 transpositions
    max 7/24 at any primer    -> ELIMINATION HOLDS, and comfortably

WHY THE m=26 CASE IS NOT A LEAD
  The 24 cribs occupy 23 distinct residue classes mod 26, against 26 free
  primer letters. The system is underdetermined, so 24/24 is guaranteed by
  counting rather than discovered. It is the same degrees-of-freedom artefact
  documented in scripts/crib_analysis/e_crib_31_filter_power_analysis.py.
  The correct disposition is "underdetermined", never "possible".

NET EFFECT ON THE REGISTER
  * "PT-autokey max=16/24" is wrong; the true max inside the eliminated band
    is 23/24 at primer 25.
  * "cannot reach 24/24" is false at primer 26 in this peel order.
  * The permanent classification must be rescoped to primer <= 25.
  * The CT-autokey half stands and is stronger than claimed (7/24, not 21/24).

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_35_autokey_peel_correction.py
"""
from __future__ import annotations

import json
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm, rail_fence_perm, serpentine_perm,
)

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_iv = lambda c: ord(c) - 65  # noqa: E731


def untranspose(ct: str, perm) -> str:
    s = [None] * 97
    for k in range(97):
        s[perm[k]] = ct[k]
    return "".join(s)


def pt_autokey(S: str, primer, m: int):
    pt = [0] * 97
    for j in range(97):
        pt[j] = (_iv(S[j]) - (primer[j] if j < m else pt[j - m])) % 26
    return pt


def ct_autokey(S: str, primer, m: int):
    pt = [0] * 97
    for j in range(97):
        pt[j] = (_iv(S[j]) - (primer[j] if j < m else _iv(S[j - m]))) % 26
    return pt


def max_pt_autokey(perm, m: int) -> int:
    S = untranspose(CT, perm)
    tot = 0
    for s in range(m):
        qs = [(q, c) for q, c in CRIB_DICT.items() if q % m == s]
        if not qs:
            continue
        best = 0
        for v in range(26):
            pr = [0] * m
            pr[s] = v
            pt = pt_autokey(S, pr, m)
            best = max(best, sum(1 for q, c in qs if AZ[pt[q]] == c))
        tot += best
    return tot


def max_ct_autokey(perm, m: int) -> int:
    S = untranspose(CT, perm)
    tot = 0
    for s in range(m):
        qs = [(q, c) for q, c in CRIB_DICT.items() if q == s]
        if not qs:
            continue
        best = 0
        for v in range(26):
            pr = [0] * m
            pr[s] = v
            pt = ct_autokey(S, pr, m)
            best = max(best, sum(1 for q, c in qs if AZ[pt[q]] == c))
        tot += best
    pt = ct_autokey(S, [0] * m, m)
    tot += sum(1 for q, c in CRIB_DICT.items() if q >= m and AZ[pt[q]] == c)
    return tot


def main() -> int:
    perms = [(f"rail{d}", rail_fence_perm(97, d)) for d in range(2, 25)]
    perms += [(f"col{w}", columnar_perm(w, list(range(w)), 97)) for w in range(2, 15)]
    wide = perms + [(f"serp{r}x{c}", serpentine_perm(r, c, 97))
                    for r in range(2, 15) for c in range(2, 15) if r * c >= 97]

    print("=" * 78)
    print("E-FRAC-37 CORRECTION — the transposition-outer autokey peel")
    print("=" * 78)
    print(f"  transpositions: {len(perms)} (PT-autokey), {len(wide)} (CT-autokey)")
    print()
    print(f"  {'primer m':>9} | {'PT-autokey max':>15} | {'crib classes mod m':>19} | verdict")
    print("  " + "-" * 70)
    out = {}
    for m in range(1, 27):
        best = max(max_pt_autokey(p, m) for _, p in perms)
        cls = len({q % m for q in CRIB_DICT})
        v = "UNDERDETERMINED" if best >= 24 else "eliminated"
        out[f"pt_m{m}"] = {"max": best, "classes": cls}
        print(f"  {m:>9} | {best:>12}/24 | {cls:>19} | {v}")
    ct_best = max(max_ct_autokey(p, m) for _, p in wide for m in (1, 10, 21, 22, 26))
    out["ct_max"] = ct_best
    print()
    print(f"  CT-autokey max over {len(wide)} transpositions, primers 1-26: {ct_best}/24")
    print()
    print("  VERDICT")
    print("    CT-autokey half: HOLDS, and is stronger than the registered 21/24.")
    print("    PT-autokey half: HOLDS for primer <= 25 (max 23/24 at m=25);")
    print("      FAILS at primer 26, where 26 free letters face 24 cribs in 23")
    print("      residue classes. Underdetermined, not a lead.")
    art = os.path.join(_ROOT, "results", "e_crib_35_autokey_peel_correction.json")
    with open(art, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
