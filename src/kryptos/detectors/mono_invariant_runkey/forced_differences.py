"""Mono-invariant forced running-key differences for the two model orderings.

Convention: kernel route perm ``perm`` maps PT position p -> CT position perm[p]
(because decryption does I[j]=CT[perm[j]]). All values are mod-26 ints.

Model 1 (mono-inner, runkey-outer): PT->sigma->trans->+K->CT.
  Same-PT-letter crib pairs (p1,p2): delta = +/-(CT[perm[p1]] - CT[perm[p2]]) mod 26,
  lag = |perm[p1]-perm[p2]| (running key is CT-indexed). sigma cancels -> invariant.
  Sign: vigenere/beaufort -> +, var_beaufort -> - .

Model 2 (runkey-inner, mono-outer): PT->+K->trans->sigma->CT.
  Crib pairs whose CT-images collide (CT[perm[p1]]==CT[perm[p2]]):
  delta = +/-(PT diff) mod 26, lag = |p1-p2| (running key is PT-indexed). sigma cancels.
  vigenere -> PT[p2]-PT[p1]; beaufort/var_beaufort -> PT[p1]-PT[p2].
"""
from __future__ import annotations
from itertools import combinations
from typing import List, Sequence, Tuple

Diff = Tuple[int, int]  # (delta mod 26, lag)
_VARIANTS = ("vigenere", "beaufort", "var_beaufort")


def forced_diffs_model1(ct_idx: Sequence[int], crib_items: Sequence[Tuple[int, int]],
                        perm: Sequence[int], variant: str) -> List[Diff]:
    assert variant in _VARIANTS, variant
    by_letter: dict[int, list[int]] = {}
    for pt_pos, pt_idx in crib_items:
        by_letter.setdefault(pt_idx, []).append(pt_pos)
    out: List[Diff] = []
    for positions in by_letter.values():
        for p1, p2 in combinations(sorted(positions), 2):
            c1, c2 = ct_idx[perm[p1]], ct_idx[perm[p2]]
            delta = (c1 - c2) % 26
            if variant == "var_beaufort":
                delta = (-delta) % 26
            lag = abs(perm[p1] - perm[p2])
            out.append((delta, lag))
    return out


def forced_diffs_model2(ct_idx: Sequence[int], crib_items: Sequence[Tuple[int, int]],
                        perm: Sequence[int], variant: str) -> List[Diff]:
    assert variant in _VARIANTS, variant
    out: List[Diff] = []
    for (p1, pt1), (p2, pt2) in combinations(crib_items, 2):
        if ct_idx[perm[p1]] != ct_idx[perm[p2]]:
            continue  # collision-gated
        if variant == "vigenere":
            delta = (pt2 - pt1) % 26
        else:  # beaufort, var_beaufort
            delta = (pt1 - pt2) % 26
        lag = abs(p1 - p2)
        out.append((delta, lag))
    return out
