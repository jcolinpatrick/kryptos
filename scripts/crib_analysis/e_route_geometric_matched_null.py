#!/usr/bin/env python3
"""Matched null for e_route_geometric_periodic_ceiling.

The ceiling filter becomes vacuous when the period is large enough that crib
positions rarely share a residue class. This measures HOW vacuous, by drawing
uniformly random 97-permutations in place of geometric routes and running the
identical filter. Survivor rates at or below the null are a parameter count,
not a cryptographic signal.
"""
from __future__ import annotations
import os, random, sys
from collections import defaultdict
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
from crib_filter import ceiling, sub_inner, sub_outer  # noqa: E402
import crib_sets  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402

TRIALS = 20000
rng = random.Random(20260825)
d0 = crib_sets.level("L0_released")
n = len(d0)
cnt = defaultdict(int)
for _ in range(TRIALS):
    perm = list(range(97)); rng.shuffle(perm)
    for peel, b in (("sub_outer", sub_outer), ("sub_inner", sub_inner)):
        for p in range(1, 31):
            a, c = b(perm, p)
            if ceiling(CT, d0, a, c, variant="vig")[0] == n:
                cnt[(peel, p)] += 1
print(f"matched null, {TRIALS} uniform random 97-permutations, L0 (n=24), vig, AZ/AZ")
for peel in ("sub_outer", "sub_inner"):
    print(peel, " ".join(f"{p}:{cnt[(peel,p)]/TRIALS:.4f}" for p in range(18, 31)))
