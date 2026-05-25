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

    # Pre-materialise per-position (ct_idx, pt_idx) pairs once.  Avoids a
    # closure-call overhead that becomes significant when this function is
    # invoked thousands of times (e.g., once per Hamming-1 CT variant in the
    # Stage-A sweep).
    ci = [index_table[ord(ct[p]) - 65] for p in positions]
    pi = [index_table[ord(crib_dict[p]) - 65] for p in positions]

    eq: list[Tuple[int, int]] = []
    ineq: list[Tuple[int, int]] = []
    linear: list[Tuple[int, int, int, int]] = []

    for i in range(n):
        for j in range(i + 1, n):
            a, b = positions[i], positions[j]
            ca, pa = ci[i], pi[i]
            cb, pb = ci[j], pi[j]
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
                    for ri, rj, rk, rl in ((i, j, k, l), (i, k, j, l), (i, l, j, k)):
                        ca, pa = ci[ri], pi[ri]
                        cb, pb = ci[rj], pi[rj]
                        cc, pc = ci[rk], pi[rk]
                        cd, pd = ci[rl], pi[rl]
                        vig = ((ca - pa) - (cb - pb) - (cc - pc) + (cd - pd)) % mod
                        beau = ((ca + pa) - (cb + pb) - (cc + pc) + (cd + pd)) % mod
                        vbeau = ((pa - ca) - (pb - cb) - (pc - cc) + (pd - cd)) % mod
                        if vig == 0 and beau == 0 and vbeau == 0:
                            linear.append((positions[ri], positions[rj], positions[rk], positions[rl]))

    return tuple(eq), tuple(ineq), tuple(linear)
