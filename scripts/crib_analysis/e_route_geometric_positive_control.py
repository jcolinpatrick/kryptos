#!/usr/bin/env python3
"""Positive control for e_route_geometric_periodic_ceiling.

A filter that only ever says "impossible" is useless and can be wrong in the
dangerous direction. Here we SYNTHESISE ciphertexts from known geometric-route
+ periodic-substitution configurations and require that the sweep's own route
builder + ceiling call never eliminate the truth, and that the per-class
majority shift recovers the true key.
"""
from __future__ import annotations
import os, random, sys
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "crib_analysis"))

from crib_filter import AZ, MOD, ceiling, index_table, inverse, sub_inner, sub_outer
import crib_sets
from e_route_geometric_periodic_ceiling import KA, N, build_routes, grid_op_perm, ragged_turn_perm
from kryptos.kernel.transforms.transposition import (
    canonical_diagonal_perm, diagonal_perm, rail_fence_perm, serpentine_perm, spiral_perm)


def synth(pt, perm, period, key, variant, ct_alpha, pt_alpha, frame):
    ct_tab, pt_tab = index_table(ct_alpha), index_table(pt_alpha)
    ip = inverse(perm)
    ct = [None] * len(pt)
    for q, ch in enumerate(pt):
        j = ip[q]
        s = key[(j if frame == "ct" else q) % period]
        p = pt_tab[ord(ch) - 65]
        if variant == "vig":
            c = (p + s) % MOD
        elif variant == "beau":
            c = (s - p) % MOD
        else:
            c = (p - s) % MOD
        ct[j] = ct_alpha[c]
    return "".join(ct)


def main():
    rng = random.Random(20260825)
    routes = [
        ("rail7", rail_fence_perm(N, 7)),
        ("serpH11", serpentine_perm(9, 11, N, False)),
        ("serpV13", serpentine_perm(8, 13, N, True)),
        ("spiral9cw", spiral_perm(11, 9, N, True)),
        ("spiral14ccw", spiral_perm(7, 14, N, False, start_corner="bottom_right")),
        ("canondiag8", canonical_diagonal_perm(8, N)),
        ("diag10_main_rev", diagonal_perm(10, 10, N, axis="main", order="reverse",
                                          start_edge="left_then_top", cell_order="alternate")),
        ("raggedturn12cw", ragged_turn_perm(N, 12, "cw")),
        ("gridop7_RL_BU", grid_op_perm(N, 7, "ROW_RL", "COL_BU")),
    ]
    fails = trials = 0
    for rname, perm in routes:
        assert sorted(perm) == list(range(N)), rname
        for frame, builder in (("ct", sub_outer), ("pt", sub_inner)):
            for variant in ("vig", "beau", "vbeau"):
                for ca, pa in ((AZ, AZ), (KA, AZ), (AZ, KA), (KA, KA)):
                    for period in (3, 7, 8, 10, 17):
                        trials += 1
                        key = [rng.randrange(MOD) for _ in range(period)]
                        pt = "".join(rng.choice(AZ) for _ in range(N))
                        ct = synth(pt, perm, period, key, variant, ca, pa, frame)
                        for lname in crib_sets.LEVELS:
                            d = crib_sets.level(lname)
                            cribs = {q: pt[q] for q in d}
                            align, cls = builder(perm, period)
                            ceil, classes = ceiling(ct, cribs, align, cls,
                                                    ct_tab=index_table(ca),
                                                    pt_tab=index_table(pa),
                                                    variant=variant)
                            if ceil != len(cribs):
                                fails += 1
                                print(f"FAIL truth eliminated: {rname} {frame} {variant} "
                                      f"p={period} {lname} {ceil}/{len(cribs)}")
                        # key recovery on the full-crib (L4-sized) set
                        cribs = {q: pt[q] for q in range(N)}
                        align, cls = builder(perm, period)
                        _c, classes = ceiling(ct, cribs, align, cls,
                                              ct_tab=index_table(ca),
                                              pt_tab=index_table(pa), variant=variant)
                        for c, dd in classes.items():
                            best = max(dd, key=lambda t: dd[t])
                            if best != key[c]:
                                fails += 1
                                print(f"FAIL key recovery {rname} {frame} {variant} p={period} cls={c}")
    print(f"positive control: {trials} configurations x 6 crib levels, {fails} failures")

    # negative control: random permutations must mostly be eliminated at L0
    d0 = crib_sets.level("L0_released")
    from kryptos.kernel.constants import CT
    surv = 0
    trials2 = 2000
    for _ in range(trials2):
        perm = list(range(N)); rng.shuffle(perm)
        align, cls = sub_outer(perm, 7)
        c, _ = ceiling(CT, d0, align, cls, variant="vig")
        if c == len(d0):
            surv += 1
    print(f"negative control: {surv}/{trials2} random perms survive L0 at period 7 "
          f"(sub_outer, vig, AZ/AZ)")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
