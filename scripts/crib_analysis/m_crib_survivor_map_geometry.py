"""Crib-ladder geometry facts underpinning the survivor map.

HYPOTHESIS: none. This is not a sweep and tests no cipher. It measures three
properties of the six crib levels that the survivor map's cross-family claims
rest on, so that those claims are derived rather than asserted:

  1. Nesting.  If L_a subset L_b then the crib deficit (n - ceiling) is monotone
     non-decreasing from a to b, so an elimination at L_a implies one at L_b.
     This is why the L1..L5 columns are not five independent results.
  2. Mutual exclusivity.  L3 and L4/L5 disagree at position 34 (X vs R), so at
     most one of them can be true.  L4 and L5 differ at only two positions.
  3. Structural vacuity thresholds.  For the sub_inner peel the key class is
     (position mod P), so once every crib position is distinct mod P the ceiling
     equals n by construction and the filter asserts nothing.  Printing the
     exact vacuous period set per level bounds where any periodic result can
     possibly have power.

PRE-REGISTERED INTERPRETATION: these are deterministic properties of the crib
sets, not evidence about K4.  A period listed as vacuous is NOT eliminated and
NOT surviving -- the filter is silent there.

Run: PYTHONPATH=src python3 scripts/crib_analysis/m_crib_survivor_map_geometry.py
"""
from __future__ import annotations

import itertools
import json
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from lib import crib_sets as CS  # noqa: E402


def main() -> None:
    levels = {name: CS.level(name) for name in CS.LEVELS}
    out: dict[str, object] = {}

    out["sizes"] = {n: len(d) for n, d in levels.items()}

    nesting = []
    for a, b in itertools.permutations(CS.LEVELS, 2):
        A, B = levels[a], levels[b]
        if len(A) < len(B) and all(k in B and B[k] == v for k, v in A.items()):
            nesting.append([a, b])
    out["strict_subset_pairs"] = nesting

    conflicts = {}
    for a, b in itertools.combinations(CS.LEVELS, 2):
        A, B = levels[a], levels[b]
        bad = sorted(k for k in A if k in B and A[k] != B[k])
        if bad:
            conflicts[f"{a}|{b}"] = bad
    out["conflicting_positions"] = conflicts

    vac = {}
    for name, d in levels.items():
        pos = sorted(d)
        vacuous = [P for P in range(1, 98)
                   if len({p % P for p in pos}) == len(pos)]
        permanent = next((P for P in range(1, 98)
                          if all(len({p % Q for p in pos}) == len(pos)
                                 for Q in range(P, 200))), None)
        vac[name] = {
            "n_cribs": len(pos),
            "span": [pos[0], pos[-1]],
            "unconstrained_tail": [pos[-1] + 1, 96],
            "sub_inner_vacuous_periods": vacuous,
            "permanently_vacuous_from_period": permanent,
        }
    out["vacuity"] = vac

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
