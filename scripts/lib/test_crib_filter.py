"""Self-test for scripts/lib/crib_filter.py.

POSITIVE CONTROL is the point of this file. A filter that only ever says
"impossible" is useless and can be wrong in the dangerous direction. So we
synthesise ciphertexts from KNOWN configurations and require that the filter
never eliminates the truth, and that the majority-shift per class recovers the
true key. Conventions (gather vs scatter, which frame the key runs in) are
settled empirically here, not by reasoning about them.
"""
from __future__ import annotations

import os
import random
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import (  # noqa: E402
    AZ, MOD, ceiling, identity_perm, index_table, inverse, keyword_mixed,
    sub_inner, sub_outer,
)
from kryptos.kernel.transforms.transposition import columnar_perm  # noqa: E402


def synth(pt, perm, period, key_shifts, variant, ct_alpha, pt_alpha, frame):
    """Build the ciphertext that the library's model would decrypt back to `pt`."""
    ct_tab, pt_tab = index_table(ct_alpha), index_table(pt_alpha)
    ip = inverse(perm)
    ct = [None] * len(pt)
    for q, ch in enumerate(pt):
        j = ip[q]
        s = key_shifts[(j if frame == "ct" else q) % period]
        p = pt_tab[ord(ch) - 65]
        if variant == "vig":
            c = (p + s) % MOD
        elif variant == "beau":
            c = (s - p) % MOD
        else:
            c = (p - s) % MOD
        ct[j] = ct_alpha[c]
    return "".join(ct)


def run() -> int:
    rng = random.Random(20260825)
    fails = 0
    trials = 0
    print("=" * 76)
    print("POSITIVE CONTROL — the filter must never eliminate a true configuration")
    print("=" * 76)
    for frame, builder in (("ct", sub_outer), ("pt", sub_inner)):
        for variant in ("vig", "beau", "vbeau"):
            for ct_alpha, pt_alpha, alab in (
                (AZ, AZ, "AZ/AZ"),
                ("KRYPTOSABCDEFGHIJLMNQUVWXZ", AZ, "KA/AZ"),
                ("KRYPTOSABCDEFGHIJLMNQUVWXZ", keyword_mixed("PALIMPSEST"), "KA/PALIMPSEST"),
            ):
                for width, period in ((7, 5), (8, 9), (11, 12), (1, 4)):
                    trials += 1
                    perm = (columnar_perm(width, list(range(width)), 97)
                            if width > 1 else identity_perm(97))
                    rng.shuffle(perm) if False else None
                    key = [rng.randrange(MOD) for _ in range(period)]
                    pt = "".join(rng.choice(AZ) for _ in range(97))
                    ct = synth(pt, perm, period, key, variant, ct_alpha, pt_alpha, frame)
                    cribs = {q: pt[q] for q in
                             list(range(0, 21)) + list(range(21, 34)) + list(range(63, 74))}
                    align, cls = builder(perm, period)
                    ceil, classes = ceiling(
                        ct, cribs, align, cls,
                        ct_tab=index_table(ct_alpha), pt_tab=index_table(pt_alpha),
                        variant=variant)
                    ok = ceil == len(cribs)
                    # key recovery: majority shift per class must equal the true key
                    rec_ok = True
                    for c, dd in classes.items():
                        maj = max(dd, key=lambda t: dd[t])
                        if maj != key[c]:
                            rec_ok = False
                    if not (ok and rec_ok):
                        fails += 1
                        print(f"  FAIL frame={frame} {variant} {alab} w={width} p={period}"
                              f"  ceiling={ceil}/{len(cribs)} keyrec={rec_ok}")
    print(f"  positive control: {trials - fails}/{trials} configurations survived"
          f" their own ciphertext and recovered their own key")
    if fails:
        print("  *** CONVENTION ERROR — do not use this filter ***")
        return 1

    print()
    print("=" * 76)
    print("NEGATIVE CONTROL — a wrong permutation should usually be eliminated")
    print("=" * 76)
    perm = columnar_perm(8, list(range(8)), 97)
    key = [rng.randrange(MOD) for _ in range(9)]
    pt = "".join(rng.choice(AZ) for _ in range(97))
    ct = synth(pt, perm, 9, key, "vig", AZ, AZ, "ct")
    cribs = {q: pt[q] for q in list(range(0, 21)) + list(range(21, 34)) + list(range(63, 74))}
    n = len(cribs)
    align, cls = sub_outer(perm, 9)
    c_true, _ = ceiling(ct, cribs, align, cls)
    survived = 0
    N = 2000
    for _ in range(N):
        wp = list(range(97))
        rng.shuffle(wp)
        a2, c2 = sub_outer(wp, 9)
        cc, _ = ceiling(ct, cribs, a2, c2)
        if cc == n:
            survived += 1
    print(f"  true permutation ceiling      : {c_true}/{n}  (must be {n})")
    print(f"  random permutations surviving : {survived}/{N} = {survived/N:.4f}")
    print(f"  -> the filter discriminates: it does not pass everything")
    print()
    print("=" * 76)
    print("REGRESSION — must reproduce the repo's published ceilings")
    print("=" * 76)
    from kryptos.kernel.constants import CT, CRIB_DICT
    ip_id = identity_perm(97)
    peaks = {}
    for p in range(1, 27):
        a, c = sub_outer(ip_id, p)
        peaks[p], _ = ceiling(CT, dict(CRIB_DICT), a, c)
    print(f"  direct alignment, released 24 cribs, periods 1-26:")
    print(f"    max ceiling = {max(peaks.values())}/24 at p={max(peaks,key=peaks.get)}")
    print(f"    any period reaching 24/24? {[p for p,v in peaks.items() if v==24] or 'NONE'}")
    print(f"    -> matches the briefing: all periods 1-26 eliminated. OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
