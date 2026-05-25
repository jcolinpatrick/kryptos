"""Pure, dependency-free Bean-constraint derivation.

Imports NOTHING from the kernel so that constants.py can call it without a
circular import. Operates entirely on explicit arguments: the ciphertext, a
crib mapping (0-indexed position -> uppercase letter), a 26-entry index table
(index_table[ord(ch)-65] -> position-in-alphabet), and the modulus.

Variant-independent: a pair/tuple is admitted only when the relation holds for
ALL three additive variants (Vigenere k=c-p, Beaufort k=c+p, VarBeaufort k=p-c).
Output sets are in 0-indexed CT coordinates.
"""
from __future__ import annotations

from typing import Mapping, Sequence, Tuple

BeanConstraints = Tuple[
    Tuple[Tuple[int, int], ...],
    Tuple[Tuple[int, int], ...],
    Tuple[Tuple[int, int, int, int], ...],
]


def derive_bean_constraints(
    ct: str,
    crib_dict: Mapping[int, str],
    index_table: Sequence[int],
    mod: int = 26,
) -> BeanConstraints:
    positions = sorted(crib_dict.keys())
    n = len(positions)

    def cp(pos: int) -> Tuple[int, int]:
        return index_table[ord(ct[pos]) - 65], index_table[ord(crib_dict[pos]) - 65]

    eq: list[Tuple[int, int]] = []
    ineq: list[Tuple[int, int]] = []
    linear: list[Tuple[int, int, int, int]] = []

    for i in range(n):
        for j in range(i + 1, n):
            a, b = positions[i], positions[j]
            ca, pa = cp(a)
            cb, pb = cp(b)
            vig = (ca - pa) % mod == (cb - pb) % mod
            beau = (ca + pa) % mod == (cb + pb) % mod
            vbeau = (pa - ca) % mod == (pb - cb) % mod
            if vig and beau and vbeau:
                eq.append((a, b))
            elif not vig and not beau and not vbeau:
                ineq.append((a, b))

    for i in range(n):
        for j in range(i + 1, n):
            for k in range(j + 1, n):
                for l in range(k + 1, n):
                    a, b, c, d = positions[i], positions[j], positions[k], positions[l]
                    for p1, p2, p3, p4 in ((a, b, c, d), (a, c, b, d), (a, d, b, c)):
                        ca, pa = cp(p1)
                        cb, pb = cp(p2)
                        cc, pc = cp(p3)
                        cd, pd = cp(p4)
                        vig = ((ca - pa) - (cb - pb) - (cc - pc) + (cd - pd)) % mod
                        beau = ((ca + pa) - (cb + pb) - (cc + pc) + (cd + pd)) % mod
                        vbeau = ((pa - ca) - (pb - cb) - (pc - cc) + (pd - cd)) % mod
                        if vig == 0 and beau == 0 and vbeau == 0:
                            linear.append((p1, p2, p3, p4))

    return tuple(eq), tuple(ineq), tuple(linear)
