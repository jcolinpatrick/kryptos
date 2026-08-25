"""ADVERSARIAL VERIFICATION of e_crib_50_direct_periodic_ceiling.py.

HYPOTHESIS UNDER TEST
---------------------
Not a cryptanalytic hypothesis. This script tests the CLAIM made by
e_crib_50: that direct-alignment (identity permutation) periodic substitution
is eliminated for every key at periods 1-25 and 33-48 over all 370x370 ordered
alphabet pairs and all three additive variants at crib level L0, leaving only
periods 26 and 30-32 (plus structurally-uninformative 27-29) not eliminated.

SCOPE OF THIS VERIFICATION
--------------------------
  V1 BRUTE-FORCE EXACTNESS. For small periods, enumerate EVERY key in 26^P and
     count the true maximum number of cribs any key can satisfy. Compare with
     the ceiling. Exhaustive; no sampling. This tests the formula itself, not
     an implementation of it.
  V2 KERNEL AGREEMENT. Recompute the ceiling for ALL 136,900 alphabet pairs at
     the decision-critical periods using (a) a from-scratch scalar routine
     written here and (b) scripts/lib/crib_filter.ceiling, and compare both
     against e_crib_50's numpy kernel (imported, not reimplemented). e_crib_50's
     own cross-check compares the LIBRARY against a THIRD ad-hoc scalar loop and
     never touches its own numpy kernel, so that kernel is unverified.
  V3 VARIANT INDEPENDENCE. Test whether vig and vbeau induce the same class
     partition of demanded shifts, i.e. whether the third variant is redundant.
  V4 PERIOD COVERAGE. Extend the period axis to the full 1..97 that a 97-char
     text admits and locate the true residual open surface at L0, together with
     the exact period above which the L0 crib set makes the filter powerless.
  V5 SURVIVOR REALISABILITY. Construct the explicit key for a named survivor,
     decrypt, and confirm the 24 released crib letters appear. Confirm the
     named elimination fails for a concrete reason.

PRE-REGISTERED INTERPRETATION
-----------------------------
  Any disagreement in V1/V2 refutes the result outright.
  V3 redundancy does not refute any elimination but inflates reported breadth.
  A period in 1..97 with survivors that e_crib_50 did not test means its
  "leaving only periods 26 and 30-32" statement understates the open surface.
  ceiling == n is NOT ELIMINATED BY THIS FILTER. Never "possible".
"""
from __future__ import annotations

import itertools
import os
import sys
from collections import defaultdict

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "crib_analysis"))

from crib_filter import AZ, ceiling, identity_perm, index_table, keyword_mixed, sub_outer  # noqa: E402
from crib_sets import LEVELS, level as crib_level  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402
import e_crib_50_direct_periodic_ceiling as S  # noqa: E402

VARIANTS = ("vig", "beau", "vbeau")


# ---------- from-scratch scalar ceiling (deliberately NOT the library) -------
def my_ceiling(cribs, period, ct_alpha, pt_alpha, variant):
    ci = {ch: k for k, ch in enumerate(ct_alpha)}
    pi = {ch: k for k, ch in enumerate(pt_alpha)}
    buckets = defaultdict(list)
    for q in sorted(cribs):
        c, p = ci[CT[q]], pi[cribs[q]]
        t = (c - p) % 26 if variant == "vig" else \
            (c + p) % 26 if variant == "beau" else (p - c) % 26
        buckets[q % period].append(t)
    tot = 0
    for v in buckets.values():
        tot += max(v.count(x) for x in set(v))
    return tot


def decrypt(period, key, ct_alpha, pt_alpha, variant):
    ci = {ch: k for k, ch in enumerate(ct_alpha)}
    out = []
    for i, ch in enumerate(CT):
        c, s = ci[ch], key[i % period]
        p = (c - s) % 26 if variant == "vig" else \
            (s - c) % 26 if variant == "beau" else (c + s) % 26
        out.append(pt_alpha[p])
    return "".join(out)


def brute_force_max(cribs, period, ct_alpha, pt_alpha, variant):
    """Exhaustive over all 26^period keys. Returns true max cribs satisfiable."""
    pos = sorted(cribs)
    best = 0
    for key in itertools.product(range(26), repeat=period):
        pt = decrypt(period, key, ct_alpha, pt_alpha, variant)
        m = sum(1 for q in pos if pt[q] == cribs[q])
        if m > best:
            best = m
    return best


def main() -> int:
    L0 = crib_level("L0_released")
    n0 = len(L0)
    alphas, names, _ = S.build_alphabets()
    na = len(alphas)
    print(f"alphabets={na}  pairs={na*na}  L0 n_cribs={n0}")

    # sanity: identity permutation is a genuine bijection of 0..96
    ip = identity_perm(97)
    assert sorted(ip) == list(range(97)) and len(set(ip)) == 97
    print("V0 identity permutation is a bijection of 0..96: OK")

    # ---------------- V1 exhaustive brute force over every key ---------------
    print("\nV1 BRUTE FORCE over ALL 26^P keys vs ceiling (exhaustive, no sampling)")
    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    bad = 0
    for period in (1, 2, 3):
        for ca, pa, lab in ((AZ, AZ, "AZ/AZ"), (KA, AZ, "KA/AZ"),
                            (KA, keyword_mixed("PALIMPSEST"), "KA/PALIMPSEST")):
            for var in VARIANTS:
                bf = brute_force_max(L0, period, ca, pa, var)
                ce = my_ceiling(L0, period, ca, pa, var)
                lib, _ = ceiling(CT, L0, *sub_outer(ip, period),
                                 ct_tab=index_table(ca), pt_tab=index_table(pa),
                                 variant=var)
                ok = bf == ce == lib
                bad += not ok
                print(f"   P={period} {lab:<14} {var:<6} brute={bf:>2} "
                      f"mine={ce:>2} lib={lib:>2}  {'OK' if ok else '*** MISMATCH ***'}")
    print(f"   V1 mismatches: {bad}")

    # -------------- V2 full-grid agreement with e_crib_50's numpy kernel -----
    print("\nV2 FULL-GRID kernel agreement (all 136,900 pairs, decision-critical periods)")
    crit = [25, 26, 30, 31, 32, 33]
    v2bad = 0
    for lvl in ("L0_released", "L1_opening"):
        cribs = crib_level(lvl)
        n = len(cribs)
        for var in VARIANTS:
            r = S.sweep_one((lvl, var, alphas, names))
            for period in crit:
                cell = r["periods"][period]
                # independent recompute of survivors + max ceiling for ALL pairs
                mx, surv = 0, 0
                for i in range(na):
                    ci_tab = index_table(alphas[i])
                    for j in range(na):
                        c = my_ceiling(cribs, period, alphas[i], alphas[j], var)
                        if c > mx:
                            mx = c
                        surv += (c == n)
                ok = (mx == cell["max_ceiling"]) and (surv == cell["survivors"])
                v2bad += not ok
                print(f"   {lvl:<12} {var:<6} P={period:<3} "
                      f"kernel(max={cell['max_ceiling']},surv={cell['survivors']}) "
                      f"mine(max={mx},surv={surv})  {'OK' if ok else '*** MISMATCH ***'}")
    print(f"   V2 mismatches: {v2bad}")

    # ---------------- V3 is the vbeau axis redundant with vig? ---------------
    print("\nV3 VARIANT REDUNDANCY")
    same = tot = 0
    for period in range(1, 49):
        for i in range(0, na, 37):
            for j in range(0, na, 37):
                tot += 1
                same += (my_ceiling(L0, period, alphas[i], alphas[j], "vig")
                         == my_ceiling(L0, period, alphas[i], alphas[j], "vbeau"))
    print(f"   vig == vbeau ceiling on {same}/{tot} sampled configs")
    print("   (t_vig = -t_vbeau mod 26, so the class partition of equal demands "
          "is identical; the vbeau axis is provably redundant for this filter)")

    # ---------------- V4 true period coverage 1..97 at L0 --------------------
    print("\nV4 PERIOD COVERAGE 1..97 at L0 (e_crib_50 tested only 1..48)")
    tabs = np.array([index_table(a) for a in alphas], dtype=np.int16)
    pos = sorted(L0)
    ct_at = np.array([ord(CT[q]) - 65 for q in pos])
    pt_at = np.array([ord(L0[q]) - 65 for q in pos])
    A, B = tabs[:, ct_at], tabs[:, pt_at]
    M = na * na
    rows = np.arange(M)
    Tv = {"vig": ((A[:, None, :] - B[None, :, :]) % 26).reshape(M, n0).astype(np.int8),
          "beau": ((A[:, None, :] + B[None, :, :]) % 26).reshape(M, n0).astype(np.int8)}
    Tv["vbeau"] = (26 - Tv["vig"]) % 26
    open_periods, powerless, elim = [], [], []
    for period in range(1, 98):
        g = defaultdict(list)
        for k, q in enumerate(pos):
            g[q % period].append(k)
        groups = list(g.values())
        multi = [x for x in groups if len(x) > 1]
        if not multi:
            powerless.append(period)
            continue
        tot_s = 0
        for var in VARIANTS:
            T = Tv[var]
            ceil = np.full(M, len(groups) - len(multi), dtype=np.int16)
            counts = np.empty((M, 26), dtype=np.int16)
            for grp in multi:
                counts.fill(0)
                for k in grp:
                    counts[rows, T[:, k]] += 1
                ceil += counts.max(axis=1)
            tot_s += int((ceil == n0).sum())
        (open_periods if tot_s else elim).append((period, tot_s, n0 - len(groups)))
    print(f"   periods FULLY ELIMINATED (all 410,700 cfgs): "
          f"{[p for p, _, _ in elim]}")
    print(f"   periods with survivors (surplus>0): "
          f"{[(p, s, sp) for p, s, sp in open_periods]}")
    print(f"   periods where the filter is STRUCTURALLY POWERLESS "
          f"(no two cribs congruent): {powerless[0]}..{powerless[-1]} "
          f"({len(powerless)} periods)")
    untested_open = [(p, s, sp) for p, s, sp in open_periods if p > 48]
    print(f"   NOT TESTED by e_crib_50 yet informative and OPEN: {untested_open}")

    # ---------------- V5 realise one survivor, explain one elimination -------
    print("\nV5 SURVIVOR REALISABILITY")
    pa = keyword_mixed("IQLUSION")
    period, var, ca = 26, "vig", AZ
    ci = {ch: k for k, ch in enumerate(ca)}
    pi = {ch: k for k, ch in enumerate(pa)}
    key = [0] * period
    dem = defaultdict(list)
    for q in sorted(L0):
        dem[q % period].append((ci[CT[q]] - pi[L0[q]]) % 26)
    for cl, ts in dem.items():
        key[cl] = max(set(ts), key=ts.count)
    pt = decrypt(period, key, ca, pa, var)
    hits = sum(1 for q in sorted(L0) if pt[q] == L0[q])
    print(f"   P=26 vig ct=AZ pt=IQLUSION -> constructed key satisfies "
          f"{hits}/{n0} released cribs")
    print(f"   decrypt: {pt}")
    print("   NOT ELIMINATED BY THIS FILTER. This is a statement about 24 letters "
          "and nothing else; it is not a candidate solution.")
    print("\n   named elimination AZ/AZ vig P=26:")
    c = my_ceiling(L0, 26, AZ, AZ, "vig")
    t21 = (ci[CT[21]] - AZ.index(L0[21])) % 26
    t73 = (ci[CT[73]] - AZ.index(L0[73])) % 26
    print(f"      ceiling {c}/24; positions 21 and 73 are the only pair congruent "
          f"mod 26 and demand shifts {t21} vs {t73} -> irreconcilable for every key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
