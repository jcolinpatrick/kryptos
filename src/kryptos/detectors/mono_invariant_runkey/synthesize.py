"""Build synthetic Mono+Trans+Running-key ciphertexts for detector validation.

perm maps PT position p -> CT position perm[p] (i.e. CT[perm[p]] receives PT pos p).
"""
from __future__ import annotations
from typing import List, Sequence


def synthesize_model1(pt: Sequence[int], runkey: Sequence[int], sigma: Sequence[int],
                      perm: Sequence[int], variant: str) -> List[int]:
    # PT -> sigma -> trans -> +K -> CT.  CT[perm[p]] = addkey(sigma(pt[p]), K[perm[p]])
    n = len(pt)
    ct = [0] * n
    for p in range(n):
        s = sigma[pt[p]]
        m = perm[p]
        k = runkey[m]
        if variant == "vigenere":
            ct[m] = (s + k) % 26
        elif variant == "beaufort":
            ct[m] = (k - s) % 26
        else:  # var_beaufort: CT = PT' - K
            ct[m] = (s - k) % 26
    return ct


def synthesize_model2(pt: Sequence[int], runkey: Sequence[int], sigma: Sequence[int],
                      perm: Sequence[int], variant: str) -> List[int]:
    # PT -> +K -> trans -> sigma -> CT.  W[p]=addkey(pt[p],K[p]); Z[perm[p]]=W[p]; CT=sigma(Z)
    n = len(pt)
    z = [0] * n
    for p in range(n):
        k = runkey[p]
        if variant == "vigenere":
            w = (pt[p] + k) % 26
        elif variant == "beaufort":
            w = (k - pt[p]) % 26
        else:  # var_beaufort
            w = (pt[p] - k) % 26
        z[perm[p]] = w
    return [sigma[z[i]] for i in range(n)]
